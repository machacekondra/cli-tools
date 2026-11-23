package maven

import (
	"fmt"
	"sort"
	"strings"
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
	if req.GroupID == "" || req.ArtifactID == "" {
		return nil, fmt.Errorf("package must be groupId:artifactId")
	}
	if req.NewVersion == "" {
		return nil, fmt.Errorf("target version must not be empty")
	}

	plan := &Plan{}
	// Dedupe by (file, span): several declarations can resolve to the same
	// property, and the same span must not be spliced twice.
	seen := map[string]bool{}

	// rewritable records that we found a declaration carrying a version we
	// could act on -- whether we rewrote it, refused it, or found it already
	// correct. Pinning is only right when there was no such declaration at
	// all; otherwise a re-run of a completed bump would add a redundant
	// dependencyManagement entry on every invocation.
	rewritable := false

	for _, pom := range proj.Poms {
		for _, decl := range pom.Declarations {
			if decl.Coord() != req.Coord() {
				continue
			}
			if decl.Version != "" {
				rewritable = true
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

	plan.AlreadySatisfied = rewritable && len(plan.Edits) == 0 && len(plan.Skipped) == 0

	if !rewritable && len(plan.Skipped) == 0 && req.PinIfMissing {
		edit, err := pinEdit(proj, req)
		if err != nil {
			return nil, err
		}
		plan.Edits = append(plan.Edits, *edit)
		plan.Pinned = true
	}

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

	// Ranges and hard requirements are a deliberate expression of intent and
	// cannot be replaced by a single version without changing meaning.
	if isRange(decl.Version) {
		return nil, &Skip{
			Pom:    pom.Path,
			Reason: fmt.Sprintf("version %q is a range; refusing to replace it with a fixed version", decl.Version),
		}
	}

	if name, isRef := PropertyRef(decl.Version); isRef {
		resolved, ok := proj.resolveProperty(pom, name)
		if !ok {
			return nil, &Skip{
				Pom:    pom.Path,
				Reason: fmt.Sprintf("version property ${%s} is not declared in this repository (it may come from a remote parent)", name),
			}
		}
		if drift := checkDrift(req, resolved.Value); drift != "" {
			return nil, &Skip{Pom: resolved.Pom.Path, Reason: drift}
		}
		if resolved.Value == req.NewVersion {
			return nil, nil // already at the target version
		}
		desc := fmt.Sprintf("property %s: %s -> %s", name, resolved.Value, req.NewVersion)
		if resolved.Pom.Path != pom.Path {
			desc += fmt.Sprintf(" (declared here, used by %s)", pom.Path)
		}
		return &target{pom: resolved.Pom, span: resolved.Span, property: name, description: desc}, nil
	}

	// A version that embeds a placeholder in a larger string, like
	// "${base}.1" or "${a}-${b}", has no single span that can be replaced.
	if strings.Contains(decl.Version, "${") {
		return nil, &Skip{
			Pom:    pom.Path,
			Reason: fmt.Sprintf("version %q interpolates a property into a larger string; cannot rewrite in place", decl.Version),
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
			name, isRef := PropertyRef(decl.Version)
			if !isRef || name != t.property {
				continue
			}
			// Same property name in a different file may be a different
			// property; only count it when it resolves to the same declaration.
			resolved, ok := proj.resolveProperty(pom, name)
			if ok && resolved.Pom.Path == t.pom.Path && resolved.Span == t.span {
				others[decl.Coord()] = true
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
