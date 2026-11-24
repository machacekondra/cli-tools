package maven

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Project is every POM reachable from a root POM: its modules, recursively,
// plus any parents that live inside the repository.
type Project struct {
	Root string // repository root, all Pom.Path values are relative to it
	Poms []*Pom

	// realRoot is Root with symlinks resolved, used to prove that every file
	// read or written stays inside the checkout.
	realRoot string

	byPath  map[string]*Pom
	byCoord map[string]*Pom
}

// Load reads the POM at <root>/pom.xml and follows <modules> and in-repo
// <parent> references.
//
// Parents outside the repository are not fetched. Maven would resolve them
// from a remote repository, but a version declared there is not ours to
// change, and writing a file we never read is worse than refusing.
func Load(root string) (*Project, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolving repository root %s: %w", root, err)
	}

	p := &Project{
		Root:     root,
		realRoot: realRoot,
		byPath:   map[string]*Pom{},
		byCoord:  map[string]*Pom{},
	}
	if err := p.load("pom.xml", loadRoot, nil); err != nil {
		return nil, err
	}
	if len(p.Poms) == 0 {
		return nil, fmt.Errorf("no pom.xml found in %s", root)
	}

	sort.Slice(p.Poms, func(i, j int) bool { return p.Poms[i].Path < p.Poms[j].Path })
	return p, nil
}

// loadKind says how a POM was reached, which decides what has to be true
// before it is admitted to the project.
type loadKind int

const (
	loadRoot loadKind = iota
	loadModule
	loadParent
)

func (p *Project) load(rel string, kind loadKind, from *Pom) error {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if _, seen := p.byPath[rel]; seen {
		return nil
	}
	// A module or relativePath may point outside the checkout.
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return nil
	}

	abs := filepath.Join(p.Root, filepath.FromSlash(rel))

	// The lexical check above is not enough: a module directory can be a
	// symlink pointing outside the repository, and ReadFile/WriteFile follow
	// it. Resolve the real path and require it to stay under the real root,
	// so an edit can never escape the checkout.
	contained, err := withinRoot(p.realRoot, abs)
	if err != nil {
		return err
	}
	if !contained {
		return nil
	}

	content, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // a declared module may legitimately be absent
		}
		return fmt.Errorf("reading %s: %w", rel, err)
	}

	pom, err := Parse(rel, content)
	if err != nil {
		return err
	}

	// A <relativePath> can point at any POM on disk. If an unrelated project
	// were admitted here it would be scanned for declarations and its files
	// rewritten, so the candidate has to prove it really is the parent
	// before it joins the project -- not afterwards, when it and all of its
	// own modules are already indexed.
	if kind == loadParent && !isDeclaredParent(from, pom) {
		return nil
	}

	p.byPath[rel] = pom
	p.byCoord[pom.Coord()] = pom
	p.Poms = append(p.Poms, pom)

	dir := filepath.Dir(rel)
	for _, m := range pom.Modules {
		if err := p.load(modulePath(dir, m), loadModule, pom); err != nil {
			return err
		}
	}
	if parent := parentPath(dir, pom.Parent); parent != "" {
		if err := p.load(parent, loadParent, pom); err != nil {
			return err
		}
	}
	return nil
}

// isDeclaredParent reports whether candidate is the parent that child
// declares. Maven matches on all three coordinates; checking only
// groupId:artifactId would accept a local copy at a different version, whose
// properties are not the ones the child actually inherits.
func isDeclaredParent(child, candidate *Pom) bool {
	if child == nil || child.Parent == nil {
		return false
	}
	ref := child.Parent
	if candidate.Coord() != ref.GroupID+":"+ref.ArtifactID {
		return false
	}
	// An absent version on either side cannot be compared; the coordinate
	// match is then the strongest evidence available.
	if ref.Version == "" || candidate.Version == "" {
		return true
	}
	return ref.Version == candidate.Version
}

// withinRoot reports whether path, with every symlink resolved, is inside
// root. Missing paths are resolved via their nearest existing ancestor so a
// declared-but-absent module is simply skipped rather than erroring.
func withinRoot(root, path string) (bool, error) {
	resolved, err := resolveExisting(path)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return false, nil
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

func resolveExisting(path string) (string, error) {
	remainder := ""
	for cur := path; ; {
		got, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(got, remainder), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("resolving %s: %w", path, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return path, nil
		}
		remainder = filepath.Join(filepath.Base(cur), remainder)
		cur = parent
	}
}

// modulePath resolves a <module> entry. Maven treats it as a directory
// containing pom.xml, but tolerates a direct path to an .xml file.
func modulePath(dir, module string) string {
	if strings.HasSuffix(module, ".xml") {
		return filepath.ToSlash(filepath.Join(dir, module))
	}
	return filepath.ToSlash(filepath.Join(dir, module, "pom.xml"))
}

// parentPath resolves a <parent> to a repo-relative POM path, or "" when the
// parent is not on disk.
func parentPath(dir string, ref *ParentRef) string {
	if ref == nil {
		return ""
	}
	// An explicitly empty <relativePath/> means "resolve from the repository,
	// do not look on disk". Defaulting it to ../pom.xml the way an absent
	// element is defaulted would be wrong, and in an aggregator layout it
	// resolves to the POM itself.
	if ref.HasRelativePath && strings.TrimSpace(ref.RelativePath) == "" {
		return ""
	}

	rel := ref.RelativePath
	if rel == "" {
		rel = ".."
	}
	if !strings.HasSuffix(rel, ".xml") {
		rel = filepath.Join(rel, "pom.xml")
	}
	return filepath.ToSlash(filepath.Join(dir, rel))
}

// Pom returns the POM at a repo-relative path.
func (p *Project) Pom(path string) *Pom { return p.byPath[path] }

// ancestors returns pom and its in-repo parents, nearest first.
//
// The parent link is verified against the <parent> coordinates before it is
// followed: a path-only match would silently treat an unrelated POM as the
// parent, and then resolve properties from the wrong file.
func (p *Project) ancestors(pom *Pom) []*Pom {
	chain := []*Pom{pom}
	seen := map[string]bool{pom.Path: true}

	for cur := pom; cur.Parent != nil; {
		path := parentPath(filepath.Dir(cur.Path), cur.Parent)
		if path == "" {
			return chain
		}
		next := p.byPath[path]
		if next == nil || seen[next.Path] || !isDeclaredParent(cur, next) {
			return chain
		}
		chain = append(chain, next)
		seen[next.Path] = true
		cur = next
	}
	return chain
}

// ResolvedProperty is a property lookup result: the value, and the POM that
// declares it, which is the file an edit has to land in.
type ResolvedProperty struct {
	Property
	Pom *Pom
}

// resolveProperty looks up a property as Maven would: the POM itself first,
// then each ancestor in turn.
//
// Built-in project.* properties are handled for ${project.version} only,
// which is the one that appears as a dependency version in practice.
func (p *Project) resolveProperty(pom *Pom, name string) (ResolvedProperty, bool) {
	// "pom." is a deprecated alias for "project.".
	normalized := strings.TrimPrefix(strings.TrimPrefix(name, "pom."), "project.")

	for _, anc := range p.ancestors(pom) {
		if prop, ok := anc.Properties[name]; ok {
			return ResolvedProperty{Property: prop, Pom: anc}, true
		}
		if normalized == "version" && !anc.VersionSpan.Empty() {
			return ResolvedProperty{
				Property: Property{Name: name, Value: anc.Version, Span: anc.VersionSpan},
				Pom:      anc,
			}, true
		}
	}
	return ResolvedProperty{}, false
}

// resolveChain follows a version literal through any number of property
// indirections and returns the property that actually holds the concrete
// value -- the one an edit has to land on.
//
// A single hop is not enough: <version>${lib.version}</version> where
// lib.version is itself ${base.version} must be rewritten at base.version.
// Editing the first hop would replace an alias with a literal, and comparing
// a drift check against it would compare against "${base.version}".
func (p *Project) resolveChain(pom *Pom, version string) (ResolvedProperty, bool) {
	cur := version
	var last ResolvedProperty
	seen := map[string]bool{}

	for range 20 { // depth limit doubles as a cycle guard
		name, isRef := PropertyRef(cur)
		if !isRef {
			// A value that still embeds a placeholder in a larger string has
			// no single span to rewrite.
			if strings.Contains(cur, "${") {
				return ResolvedProperty{}, false
			}
			return last, last.Pom != nil
		}
		if seen[name] {
			return ResolvedProperty{}, false
		}
		seen[name] = true

		// The lookup context stays the POM that consumes the version, for
		// every hop. Maven assembles inheritance into an effective model and
		// only then interpolates, so a parent's alias "${base}" resolves
		// against the child's override of base, not the parent's. Switching
		// context to the declaring POM here read the parent's value and
		// edited the wrong property.
		resolved, ok := p.resolveProperty(pom, name)
		if !ok {
			return ResolvedProperty{}, false
		}
		// An ambiguous hop must stop the walk. Continuing would replace it
		// with whatever unambiguous literal it happens to point at, and we
		// would edit that confidently while another profile's chain still
		// pointed somewhere else.
		if resolved.Unsafe != "" {
			return resolved, true
		}
		last = resolved
		cur = resolved.Value
	}
	return ResolvedProperty{}, false
}

// resolveVersion expands a version literal to a concrete version. It returns
// ok=false if the value cannot be fully resolved (an unknown property, a
// cycle, or a placeholder embedded in a larger string).
func (p *Project) resolveVersion(pom *Pom, version string) (string, bool) {
	if _, isRef := PropertyRef(version); !isRef {
		return version, !strings.Contains(version, "${")
	}
	resolved, ok := p.resolveChain(pom, version)
	if !ok {
		return "", false
	}
	return resolved.Value, true
}

// InheritanceRoots returns the POMs that have no in-repo parent. Each is the
// top of a separate inheritance tree, and therefore the only place a
// dependencyManagement entry can be added that the tree below it inherits.
func (p *Project) InheritanceRoots() []*Pom {
	var roots []*Pom
	for _, pom := range p.Poms {
		if chain := p.ancestors(pom); len(chain) == 1 {
			roots = append(roots, pom)
		}
	}
	return roots
}

// inheritanceRootOf returns the top of pom's inheritance tree, which is the
// POM whose dependencyManagement pom inherits.
func (p *Project) inheritanceRootOf(pom *Pom) *Pom {
	chain := p.ancestors(pom)
	return chain[len(chain)-1]
}
