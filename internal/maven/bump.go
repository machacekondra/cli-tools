package maven

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// Request describes the bump to perform. The coordinate and target version
// come from an external source (an SBOM scanner), so no version discovery or
// range resolution happens here.
type Request struct {
	GroupID    string
	ArtifactID string
	NewVersion string

	// CurrentVersion, when set, is a drift check: if the resolved version on
	// disk differs, the bump is refused rather than silently overwriting a
	// value someone else already changed.
	CurrentVersion string

	// PinIfMissing adds a <dependencyManagement> entry when the artifact is
	// not declared anywhere. SBOM findings are mostly transitive, so without
	// this the common case is a silent no-op.
	PinIfMissing bool
}

// Coord is the groupId:artifactId this request targets.
func (r Request) Coord() string { return r.GroupID + ":" + r.ArtifactID }

// validate rejects inputs that cannot be written into a POM as-is.
//
// These values reach us from an LLM remediation step, so they are not
// guaranteed well formed. Rejecting is the right answer rather than XML
// escaping: a version containing '&' is a bad input, and silently turning it
// into "&amp;" would produce a valid POM that declares a nonsense version.
func (r Request) validate() error {
	if r.GroupID == "" || r.ArtifactID == "" {
		return fmt.Errorf("package must be groupId:artifactId")
	}
	if r.NewVersion == "" {
		return fmt.Errorf("target version must not be empty")
	}
	// Writing a range as the target would leave the declaration holding a
	// range, which the next run then refuses as unrewritable -- so the
	// repository ends up in a state this tool cannot move out of.
	if isRange(r.NewVersion) {
		return fmt.Errorf("target version %q is a range; a fixed version is required", r.NewVersion)
	}
	// Writing a property expression as the target substitutes one
	// indirection for a concrete version, and the next run then refuses the
	// declaration because the property does not resolve. Whatever the
	// expression was meant to mean, it is not a version.
	if strings.Contains(r.NewVersion, "${") {
		return fmt.Errorf("target version %q is a property expression; a literal version is required", r.NewVersion)
	}
	for _, f := range []struct{ name, value string }{
		{"groupId", r.GroupID},
		{"artifactId", r.ArtifactID},
		{"version", r.NewVersion},
		{"current version", r.CurrentVersion},
	} {
		if f.value == "" {
			continue
		}
		if !utf8.ValidString(f.value) {
			return fmt.Errorf("%s is not valid UTF-8", f.name)
		}
		for _, c := range f.value {
			if invalidInCoordinate(c) {
				return fmt.Errorf("%s %q contains an unsupported character %q", f.name, f.value, c)
			}
		}
	}
	return nil
}

// invalidInCoordinate reports characters that may not appear in a Maven
// coordinate or version: XML metacharacters, quotes, whitespace, control
// characters, and anything outside the XML 1.0 character range.
//
// The last group matters because a value like U+FFFE survives a naive check
// and is written verbatim, after which the POM no longer parses -- the tool
// would report a successful bump and leave behind a file Maven cannot read.
func invalidInCoordinate(r rune) bool {
	switch r {
	case '<', '>', '&', '"', '\'':
		return true
	}
	if r <= ' ' || r == 0x7f {
		return true
	}
	return !validXMLChar(r)
}

// validXMLChar implements the Char production from the XML 1.0 specification.
func validXMLChar(r rune) bool {
	switch {
	case r == 0x09 || r == 0x0a || r == 0x0d:
		return true
	case r >= 0x20 && r <= 0xd7ff:
		return true
	case r >= 0xe000 && r <= 0xfffd:
		return true
	case r >= 0x10000 && r <= 0x10ffff:
		return true
	}
	return false
}

// Edit is one byte-range splice.
type Edit struct {
	Path        string
	Span        Span
	Replacement string
	Description string
}

// Plan is the set of edits that satisfy a Request, plus what the caller
// should be told about them.
type Plan struct {
	Edits []Edit

	// Pinned is set when the artifact was not declared and a new
	// dependencyManagement entry was synthesised.
	Pinned bool

	// AlreadySatisfied is set when a declaration was found already holding
	// the target version. That is a successful no-op, distinct from finding
	// nothing at all, which is a problem worth failing on.
	AlreadySatisfied bool

	// SharedProperties records properties that back more than one artifact.
	// Bumping them moves every listed coordinate, not just the requested one.
	SharedProperties []SharedProperty

	// Skipped explains declarations that matched but were deliberately not
	// rewritten, so a no-op is never silent.
	Skipped []Skip
}

// SharedProperty is a property edit that affects artifacts beyond the target.
type SharedProperty struct {
	Name        string
	Pom         string
	AlsoAffects []string
}

// Skip is a matched declaration that was intentionally left alone.
type Skip struct {
	Pom    string
	Reason string
}

// Empty reports whether the plan would change nothing.
func (p *Plan) Empty() bool { return len(p.Edits) == 0 }

// BumpProject computes the edits needed to move an artifact to a new version.
//
// Declarations are matched on groupId:artifactId only. Classifier, type and
// scope are recorded but not matched on: an SBOM finding names a vulnerable
// artifact, and every declaration of it needs the fix, not just the one whose
// classifier happens to line up.
func BumpProject(proj *Project, req Request) (*Plan, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}

	plan := &Plan{}
	// Dedupe by (file, span): several declarations can resolve to the same
	// property, and the same span must not be spliced twice.
	seen := map[string]bool{}

	// covered records, per inheritance root, that the artifact is already
	// declared with a version somewhere in that root's tree -- whether we
	// rewrote it, refused it, or found it already correct.
	//
	// This is tracked per root rather than globally because
	// dependencyManagement is inherited, not shared. If a previous run
	// pinned root A and failed before pinning root B, a global flag would
	// see A's new entry, conclude the work was done and report success
	// while B stayed vulnerable.
	covered := map[string]bool{}

	for _, pom := range proj.Poms {
		for _, decl := range pom.Declarations {
			if decl.Coord() != req.Coord() {
				continue
			}
			if decl.Version != "" {
				covered[proj.inheritanceRootOf(pom).Path] = true
			}
			target, skip := resolveTarget(proj, pom, decl, req)
			if skip != nil {
				plan.Skipped = append(plan.Skipped, *skip)
				continue
			}
			if target == nil {
				continue
			}

			key := fmt.Sprintf("%s:%d-%d", target.pom.Path, target.span.Start, target.span.End)
			if seen[key] {
				continue
			}
			seen[key] = true

			plan.Edits = append(plan.Edits, Edit{
				Path:        target.pom.Path,
				Span:        target.span,
				Replacement: req.NewVersion,
				Description: target.description,
			})

			if target.property != "" {
				if shared := sharedProperty(proj, target, req); shared != nil {
					plan.SharedProperties = append(plan.SharedProperties, *shared)
				}
			}
		}
	}

	// Pin only the inheritance roots whose tree does not already declare the
	// artifact, so a retry after a partially applied pin completes the job
	// instead of concluding it was already done.
	var uncovered []*Pom
	for _, root := range proj.InheritanceRoots() {
		if !covered[root.Path] {
			uncovered = append(uncovered, root)
		}
	}

	if len(uncovered) > 0 && len(plan.Skipped) == 0 && req.PinIfMissing {
		edits, err := pinEdits(uncovered, req)
		if err != nil {
			return nil, err
		}
		plan.Edits = append(plan.Edits, edits...)
		plan.Pinned = true
	}

	// Every inheritance root has to be covered only when pinning is on,
	// because only then can the missing ones be filled in. With pinning off
	// the caller has said to rewrite existing declarations and nothing more,
	// so a root that simply does not declare the artifact is out of scope --
	// treating it as incomplete made the command exit non-zero even though
	// the requested version was already in place everywhere it appears.
	rootsCovered := !req.PinIfMissing || len(uncovered) == 0

	plan.AlreadySatisfied = len(covered) > 0 && rootsCovered &&
		len(plan.Edits) == 0 && len(plan.Skipped) == 0

	sort.Slice(plan.Edits, func(i, j int) bool {
		if plan.Edits[i].Path != plan.Edits[j].Path {
			return plan.Edits[i].Path < plan.Edits[j].Path
		}
		return plan.Edits[i].Span.Start < plan.Edits[j].Span.Start
	})
	return plan, nil
}

// target is where a single declaration's version actually lives.
type target struct {
	pom         *Pom
	span        Span
	property    string // non-empty when the edit lands on a property value
	description string
}

func resolveTarget(proj *Project, pom *Pom, decl Declaration, req Request) (*target, *Skip) {
	// No <version> means the version is inherited from dependencyManagement
	// or a parent. There is nothing here to rewrite; whichever declaration
	// does carry the version will be matched separately.
	if decl.Version == "" {
		return nil, nil
	}

	// This must come before the property branch. A split value is recorded
	// in full but has no single span, and checking it only on the literal
	// path meant "${base}<!--c-->-tests" reached the property branch and
	// edited base, which is not what the declaration says at all.
	if decl.VersionUnsafe != "" {
		return nil, &Skip{
			Pom:    pom.Path,
			Reason: fmt.Sprintf("version %q cannot be rewritten: %s", decl.Version, decl.VersionUnsafe),
		}
	}

	if name, isRef := PropertyRef(decl.Version); isRef {
		// Follow the whole chain. The first hop may be an alias for another
		// property, and it is the terminal one that holds the real value and
		// must carry the edit.
		resolved, ok := proj.resolveChain(pom, decl.Version)
		if !ok {
			return nil, &Skip{
				Pom: pom.Path,
				Reason: fmt.Sprintf(
					"version property ${%s} does not resolve to a literal in this repository "+
						"(undeclared, cyclic, or composed from several properties)", name),
			}
		}
		if resolved.Unsafe != "" {
			return nil, &Skip{
				Pom:    resolved.Pom.Path,
				Reason: fmt.Sprintf("property %s cannot be rewritten: %s", resolved.Name, resolved.Unsafe),
			}
		}
		// Check the resolved literal, not the placeholder: a property can
		// perfectly well hold a range, and ${x} never looks like one.
		if isRange(resolved.Value) {
			return nil, &Skip{
				Pom: resolved.Pom.Path,
				Reason: fmt.Sprintf("property %s holds the range %q; refusing to replace it with a fixed version",
					resolved.Name, resolved.Value),
			}
		}
		if drift := checkDrift(req, resolved.Value); drift != "" {
			return nil, &Skip{Pom: resolved.Pom.Path, Reason: drift}
		}
		if resolved.Value == req.NewVersion {
			return nil, nil // already at the target version
		}
		desc := fmt.Sprintf("property %s: %s -> %s", resolved.Name, resolved.Value, req.NewVersion)
		if resolved.Pom.Path != pom.Path {
			desc += fmt.Sprintf(" (declared here, used by %s)", pom.Path)
		}
		return &target{
			pom:         resolved.Pom,
			span:        resolved.Span,
			property:    resolved.Name,
			description: desc,
		}, nil
	}

	// A version that embeds a placeholder in a larger string, like
	// "${base}.1" or "${a}-${b}", has no single span that can be replaced.
	if strings.Contains(decl.Version, "${") {
		return nil, &Skip{
			Pom:    pom.Path,
			Reason: fmt.Sprintf("version %q interpolates a property into a larger string; cannot rewrite in place", decl.Version),
		}
	}

	// Ranges and hard requirements are a deliberate expression of intent and
	// cannot be replaced by a single version without changing meaning.
	if isRange(decl.Version) {
		return nil, &Skip{
			Pom:    pom.Path,
			Reason: fmt.Sprintf("version %q is a range; refusing to replace it with a fixed version", decl.Version),
		}
	}

	if drift := checkDrift(req, decl.Version); drift != "" {
		return nil, &Skip{Pom: pom.Path, Reason: drift}
	}
	if decl.Version == req.NewVersion {
		return nil, nil
	}

	return &target{
		pom:         pom,
		span:        decl.VersionSpan,
		description: fmt.Sprintf("%s %s: %s -> %s", decl.Kind, decl.Coord(), decl.Version, req.NewVersion),
	}, nil
}

func checkDrift(req Request, found string) string {
	if req.CurrentVersion == "" || found == req.CurrentVersion || found == req.NewVersion {
		return ""
	}
	return fmt.Sprintf("expected current version %q but found %q; refusing to overwrite", req.CurrentVersion, found)
}

// propertyRefsIn returns the name of every ${...} placeholder in s, in order
// of appearance. A version may hold several, as in "${major}.${minor}".
func propertyRefsIn(s string) []string {
	var names []string
	for {
		open := strings.Index(s, "${")
		if open < 0 {
			return names
		}
		s = s[open+2:]
		close := strings.Index(s, "}")
		if close < 0 {
			return names
		}
		if name := strings.TrimSpace(s[:close]); name != "" {
			names = append(names, name)
		}
		s = s[close+1:]
	}
}

// isRange reports whether a Maven version is a range or hard requirement
// rather than a plain version.
func isRange(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "[") || strings.HasPrefix(v, "(") || strings.Contains(v, ",")
}

// sharedProperty reports the other artifacts that move when this property is
// bumped. Returns nil when the property backs only the requested artifact.
func sharedProperty(proj *Project, t *target, req Request) *SharedProperty {
	others := map[string]bool{}

	for _, pom := range proj.Poms {
		for _, decl := range pom.Declarations {
			if decl.Coord() == req.Coord() || decl.Version == "" {
				continue
			}
			// Take every placeholder the version mentions, whether the
			// version is exactly "${x}" or embeds it in something larger
			// like "${x}-tests", and ask where each one ends up.
			//
			// Both halves matter. A substring test alone misses a version
			// that reaches the edited property through an alias; following
			// the whole version as a chain alone misses composite
			// expressions, which never parse as a single reference. Scanning
			// the placeholders and resolving each one covers both, including
			// the combination of the two.
			for _, name := range propertyRefsIn(decl.Version) {
				// The same property name in a different file may be a
				// different property, so compare where it resolves rather
				// than trusting the name.
				resolved, ok := proj.resolveChain(pom, "${"+name+"}")
				if !ok {
					continue
				}
				if resolved.Pom.Path == t.pom.Path && resolved.Span == t.span {
					others[decl.Coord()] = true
					break
				}
			}
		}
	}
	if len(others) == 0 {
		return nil
	}

	coords := make([]string, 0, len(others))
	for c := range others {
		coords = append(coords, c)
	}
	sort.Strings(coords)
	return &SharedProperty{Name: t.property, Pom: t.pom.Path, AlsoAffects: coords}
}

// Apply returns the new content of each file the plan touches, keyed by path.
//
// Edits within a file are applied highest offset first so an earlier splice
// cannot invalidate a later span's offsets.
func Apply(proj *Project, plan *Plan) (map[string][]byte, error) {
	byFile := map[string][]Edit{}
	for _, e := range plan.Edits {
		byFile[e.Path] = append(byFile[e.Path], e)
	}

	out := map[string][]byte{}
	for path, edits := range byFile {
		pom := proj.Pom(path)
		if pom == nil {
			return nil, fmt.Errorf("plan references unknown pom %s", path)
		}

		sort.Slice(edits, func(i, j int) bool { return edits[i].Span.Start > edits[j].Span.Start })

		content := pom.Content
		prev := len(content) + 1
		for _, e := range edits {
			if e.Span.Start < 0 || e.Span.End > len(content) || e.Span.Start > e.Span.End {
				return nil, fmt.Errorf("%s: edit span %d-%d out of range", path, e.Span.Start, e.Span.End)
			}
			if e.Span.End > prev {
				return nil, fmt.Errorf("%s: overlapping edits", path)
			}
			prev = e.Span.Start

			next := make([]byte, 0, len(content)+len(e.Replacement))
			next = append(next, content[:e.Span.Start]...)
			next = append(next, e.Replacement...)
			next = append(next, content[e.Span.End:]...)
			content = next
		}
		out[path] = content
	}
	return out, nil
}
