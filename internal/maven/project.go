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
	p := &Project{
		Root:    root,
		byPath:  map[string]*Pom{},
		byCoord: map[string]*Pom{},
	}
	if err := p.load("pom.xml"); err != nil {
		return nil, err
	}
	if len(p.Poms) == 0 {
		return nil, fmt.Errorf("no pom.xml found in %s", root)
	}

	sort.Slice(p.Poms, func(i, j int) bool { return p.Poms[i].Path < p.Poms[j].Path })
	return p, nil
}

func (p *Project) load(rel string) error {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if _, seen := p.byPath[rel]; seen {
		return nil
	}
	// A module or relativePath may point outside the checkout. Refuse rather
	// than reading arbitrary files from the build host.
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return nil
	}

	abs := filepath.Join(p.Root, filepath.FromSlash(rel))
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
	p.byPath[rel] = pom
	p.byCoord[pom.Coord()] = pom
	p.Poms = append(p.Poms, pom)

	dir := filepath.Dir(rel)
	for _, m := range pom.Modules {
		if err := p.load(modulePath(dir, m)); err != nil {
			return err
		}
	}
	if parent := parentPath(dir, pom.Parent); parent != "" {
		if err := p.load(parent); err != nil {
			return err
		}
	}
	return nil
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
		if next == nil || seen[next.Path] {
			return chain
		}
		want := cur.Parent.GroupID + ":" + cur.Parent.ArtifactID
		if next.Coord() != want {
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

// resolveVersion expands a version literal to a concrete version, following
// property chains. It returns ok=false if the value cannot be fully resolved
// (an unknown property, or a cycle).
func (p *Project) resolveVersion(pom *Pom, version string) (string, bool) {
	cur := version
	seen := map[string]bool{}

	for range 10 { // depth limit doubles as a cycle guard
		name, isRef := PropertyRef(cur)
		if !isRef {
			return cur, !strings.Contains(cur, "${")
		}
		if seen[name] {
			return "", false
		}
		seen[name] = true

		resolved, ok := p.resolveProperty(pom, name)
		if !ok {
			return "", false
		}
		cur = resolved.Value
	}
	return "", false
}
