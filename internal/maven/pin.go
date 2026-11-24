package maven

import (
	"bytes"
	"fmt"
	"strings"
)

// pinEdit synthesises a <dependencyManagement> entry for an artifact that is
// not declared anywhere in the project.
//
// This is the transitive case, and for SBOM-derived findings it is the common
// one: the vulnerable artifact was pulled in by something else, so there is no
// <version> to rewrite. A dependencyManagement entry forces the resolved
// version across every module without adding a direct dependency.
//
// It is also the one path that has to produce XML rather than splice an
// existing span, so the generated text follows the file's own indentation and
// is inserted at an anchor that leaves every other byte untouched.
// pinEdits produces one entry per inheritance root.
//
// A repository can contain POMs that the top-level pom.xml aggregates as
// <modules> without being their <parent>. dependencyManagement is inherited,
// not aggregated, so a pin written only to the top-level POM leaves those
// modules resolving the vulnerable version while the command reports
// success. Every POM with no in-repo parent therefore gets its own entry.
func pinEdits(roots []*Pom, req Request) ([]Edit, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("cannot pin %s: no POM without an in-repo parent", req.Coord())
	}

	edits := make([]Edit, 0, len(roots))
	for _, root := range roots {
		edit, err := pinEdit(root, req, len(roots) > 1)
		if err != nil {
			return nil, err
		}
		edits = append(edits, *edit)
	}
	return edits, nil
}

func pinEdit(root *Pom, req Request, multipleTrees bool) (*Edit, error) {
	indent := detectIndent(root.Content, root.root)
	anchor, depth, err := pinAnchor(root)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	// Only ever insert at a point preceded by a newline, so the generated
	// block starts on a line of its own regardless of how the file is laid out.
	if anchor > 0 && root.Content[anchor-1] != '\n' {
		b.WriteString("\n")
	}
	switch depth {
	case 3: // into an existing <dependencyManagement><dependencies>
		b.WriteString(dependencyElement(indent, 3, req))
	case 1: // a whole new <dependencyManagement> under <project>
		ind := strings.Repeat(indent, 1)
		b.WriteString(ind + "<dependencyManagement>\n")
		b.WriteString(ind + indent + "<dependencies>\n")
		b.WriteString(dependencyElement(indent, 3, req))
		b.WriteString("\n" + ind + indent + "</dependencies>\n")
		b.WriteString(ind + "</dependencyManagement>\n")
	}

	desc := fmt.Sprintf("pin %s to %s via dependencyManagement (not directly declared)",
		req.Coord(), req.NewVersion)
	if multipleTrees {
		desc += " (one of several POMs with no in-repo parent)"
	}

	return &Edit{
		Path:        root.Path,
		Span:        Span{Start: anchor, End: anchor},
		Replacement: b.String(),
		Description: desc,
	}, nil
}

// dependencyElement renders the <dependency> block, without a trailing newline.
func dependencyElement(indent string, depth int, req Request) string {
	outer := strings.Repeat(indent, depth)
	inner := strings.Repeat(indent, depth+1)

	var b strings.Builder
	b.WriteString(outer + "<dependency>\n")
	b.WriteString(inner + "<groupId>" + req.GroupID + "</groupId>\n")
	b.WriteString(inner + "<artifactId>" + req.ArtifactID + "</artifactId>\n")
	b.WriteString(inner + "<version>" + req.NewVersion + "</version>\n")
	b.WriteString(outer + "</dependency>")
	return b.String()
}

// pinAnchor finds the byte offset to insert at, and the indent depth the
// inserted element sits at.
//
// Only a project-level <dependencyManagement> counts. One nested in a
// <profile> applies solely when that profile is active, so pinning there
// would leave the default build still resolving the vulnerable version.
func pinAnchor(pom *Pom) (offset int, depth int, err error) {
	dm := pom.root.child("dependencyManagement")
	if dm == nil {
		return pom.root.contentEnd, 1, nil
	}
	// Both messages name a form this function accepts on retry: an expanded
	// <dependencies></dependencies>. Suggesting the self-closing
	// <dependencies/> would send the operator straight back to the error
	// below, which rejects exactly that.
	if selfClosing(dm) {
		return 0, 0, fmt.Errorf(
			"%s: <dependencyManagement/> is self-closing; expand it to "+
				"<dependencyManagement><dependencies></dependencies></dependencyManagement> and retry",
			pom.Path)
	}

	// The two cases need different instructions. Telling someone to add
	// <dependencies></dependencies> when a self-closing <dependencies/> is
	// already there does not help: the lookup below still finds the first,
	// self-closing element and fails again.
	deps := dm.child("dependencies")
	if deps == nil {
		return 0, 0, fmt.Errorf(
			"%s: <dependencyManagement> contains no <dependencies> element; "+
				"add <dependencies></dependencies> inside it and retry",
			pom.Path)
	}
	if selfClosing(deps) {
		return 0, 0, fmt.Errorf(
			"%s: <dependencyManagement> contains a self-closing <dependencies/>; "+
				"expand that element to <dependencies></dependencies> and retry",
			pom.Path)
	}

	// Append after the last existing entry so the new one reads as part of
	// the list rather than jumping to the top of it.
	if existing := deps.childrenNamed("dependency"); len(existing) > 0 {
		return existing[len(existing)-1].span.End, 3, nil
	}
	return deps.contentStart, 3, nil
}

// selfClosing reports whether an element was written as <x/>, which has no
// interior to insert into.
func selfClosing(n *node) bool { return n.contentStart == n.span.End }

// detectIndent infers one indentation level from the file's own layout, so a
// tab-indented or four-space POM does not acquire a two-space block.
func detectIndent(content []byte, root *node) string {
	for _, c := range root.children {
		lineStart := bytes.LastIndexByte(content[:c.span.Start], '\n') + 1
		ws := content[lineStart:c.span.Start]
		if len(ws) > 0 && len(bytes.TrimLeft(ws, " \t")) == 0 {
			return string(ws)
		}
	}
	return "  "
}
