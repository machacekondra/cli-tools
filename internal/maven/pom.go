// Package maven rewrites dependency versions in Maven POM files.
//
// Edits are byte-range splices on the original file. Nothing is ever produced
// by re-serializing a parse tree: a round trip through encoding/xml would
// normalize whitespace, drop comments and reorder attributes, turning a
// one-line version bump into an unreviewable diff. The parser therefore
// records the byte span of every version literal, and the editor rewrites
// only those spans.
//
// The approach is taken from dependabot-core (MIT, Copyright (c) GitHub,
// Inc.) -- specifically its Maven file updater, declaration finder and
// property value finder. Renovate solves the same problem in the same shape,
// but it is AGPL-3.0 and no code or code structure from it was used here.
//
// One deliberate divergence from dependabot: it locates declarations with a
// recursive regex and then has to count element depth to prove a matched
// <version> is a direct child rather than something nested in a plugin's
// <configuration>. Walking encoding/xml with InputOffset() gives us the tree
// structure and the offsets at the same time, so that whole class of problem
// -- nested declarations, comments, CDATA, namespace prefixes, attributes on
// the version tag -- does not arise.
package maven

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// Span is a half-open byte range [Start, End) into a POM's raw content.
type Span struct {
	Start int
	End   int
}

// Empty reports whether the span covers no bytes.
func (s Span) Empty() bool { return s.End <= s.Start }

// Kind distinguishes the sorts of declaration that carry a version.
type Kind string

const (
	KindDependency Kind = "dependency"
	KindPlugin     Kind = "plugin"
	KindParent     Kind = "parent"
	KindExtension  Kind = "extension"
	KindPath       Kind = "annotationProcessorPath"
)

// DefaultPluginGroupID is assumed when a <plugin> omits its <groupId>, which
// Maven permits and real POMs rely on.
const DefaultPluginGroupID = "org.apache.maven.plugins"

// Declaration is one versioned artifact reference found in a POM.
type Declaration struct {
	Kind       Kind
	GroupID    string
	ArtifactID string
	Classifier string
	Type       string // packaging; "jar" unless stated, "pom" for a parent
	Scope      string
	Managed    bool // inside <dependencyManagement> or <pluginManagement>
	Profile    string

	// Version is the trimmed literal as written, so it may be "${some.prop}"
	// or a range. Empty when the element is absent, which for a dependency
	// means the version comes from dependencyManagement or a parent.
	Version string

	// VersionSpan covers exactly the version text, excluding the surrounding
	// element tags and any whitespace or comments inside them. Empty when
	// Version is empty.
	VersionSpan Span
}

// Coord returns the groupId:artifactId key this declaration matches on.
func (d Declaration) Coord() string { return d.GroupID + ":" + d.ArtifactID }

// Property is a <properties> entry.
type Property struct {
	Name    string
	Value   string
	Span    Span // the value text only
	Profile string
}

// ParentRef is a POM's <parent> block.
type ParentRef struct {
	GroupID    string
	ArtifactID string
	Version    string

	// RelativePath is the raw <relativePath> value. Absent means Maven's
	// default of "../pom.xml". Present but empty means "do not look on disk,
	// resolve from the repository" -- a distinction that matters, because
	// treating empty as absent makes a POM its own parent.
	RelativePath    string
	HasRelativePath bool
}

// Pom is a single parsed POM file.
type Pom struct {
	Path    string // path as given to Parse, used for reporting and resolution
	Content []byte

	GroupID    string
	ArtifactID string
	Version    string
	Packaging  string

	VersionSpan Span // the project's own <version>, for ${project.version}

	Parent       *ParentRef
	Modules      []string
	Properties   map[string]Property
	Declarations []Declaration

	// root is retained so the pinning path can find insertion points. Reading
	// versions never needs it.
	root *node
}

// Coord returns the POM's own groupId:artifactId, inheriting the groupId from
// its parent when omitted, as Maven does.
func (p *Pom) Coord() string {
	g := p.GroupID
	if g == "" && p.Parent != nil {
		g = p.Parent.GroupID
	}
	return g + ":" + p.ArtifactID
}

// node is a minimal XML element tree carrying byte offsets. encoding/xml does
// not expose positions on a decoded struct, so we walk tokens ourselves.
type node struct {
	name     string
	text     string
	textSpan Span // the trimmed text, empty if the element has no text
	children []*node
	span     Span // the whole element, from '<' to just past '>'

	// contentStart is just past the open tag's '>'; contentEnd is at the '<'
	// of the close tag. For a self-closing element the two are equal. They
	// give insertion points that do not disturb the surrounding bytes.
	contentStart int
	contentEnd   int
}

func (n *node) child(name string) *node {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

func (n *node) childrenNamed(name string) []*node {
	var out []*node
	for _, c := range n.children {
		if c.name == name {
			out = append(out, c)
		}
	}
	return out
}

// value returns a child's trimmed text, or "" when the child is absent.
func (n *node) value(name string) string {
	if c := n.child(name); c != nil {
		return c.text
	}
	return ""
}

// parseTree builds the element tree with spans.
//
// Element and attribute namespaces are ignored: encoding/xml reports
// Name.Local, so <version> and <mvn:version> are the same element, which is
// what Maven means.
func parseTree(data []byte) (*node, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))

	var stack []*node
	var root *node

	for {
		offset := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("offset %d: %w", offset, err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			n := &node{name: t.Name.Local}
			n.span.Start = offset
			n.contentStart = int(dec.InputOffset())
			n.contentEnd = n.contentStart
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, n)
			} else if root == nil {
				root = n
			}
			stack = append(stack, n)

		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			// Comments and processing instructions arrive as their own tokens,
			// so an element like <version>1.2.3<!--pinned--></version> yields
			// the version as a clean CharData of its own and needs no special
			// handling. Keep the last non-blank run: that also covers the
			// mirror case, <version><!--pinned-->1.2.3</version>.
			if strings.TrimSpace(string(t)) == "" {
				continue
			}
			cur := stack[len(stack)-1]
			raw := Span{Start: offset, End: int(dec.InputOffset())}
			cur.textSpan = trimSpan(data, raw)
			cur.text = string(data[cur.textSpan.Start:cur.textSpan.End])

		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			cur := stack[len(stack)-1]
			cur.contentEnd = offset
			cur.span.End = int(dec.InputOffset())
			stack = stack[:len(stack)-1]
		}
	}

	if root == nil {
		return nil, fmt.Errorf("no root element")
	}
	return root, nil
}

// trimSpan narrows a raw CharData span to its non-whitespace content, so that
// <version>  1.2.3  </version> keeps its padding when rewritten.
func trimSpan(data []byte, s Span) Span {
	raw := data[s.Start:s.End]
	lead := len(raw) - len(bytes.TrimLeft(raw, " \t\r\n"))
	trail := len(raw) - len(bytes.TrimRight(raw, " \t\r\n"))
	return Span{Start: s.Start + lead, End: s.End - trail}
}

// Parse reads a POM. path is recorded for reporting and for resolving
// relative parent and module references; it is not read from disk here.
func Parse(path string, content []byte) (*Pom, error) {
	root, err := parseTree(content)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if root.name != "project" {
		return nil, fmt.Errorf("parsing %s: root element is <%s>, not <project>", path, root.name)
	}

	p := &Pom{
		Path:       path,
		Content:    content,
		GroupID:    root.value("groupId"),
		ArtifactID: root.value("artifactId"),
		Version:    root.value("version"),
		Packaging:  root.value("packaging"),
		Properties: map[string]Property{},
		root:       root,
	}
	if v := root.child("version"); v != nil {
		p.VersionSpan = v.textSpan
	}

	if pn := root.child("parent"); pn != nil {
		rp := pn.child("relativePath")
		p.Parent = &ParentRef{
			GroupID:         pn.value("groupId"),
			ArtifactID:      pn.value("artifactId"),
			Version:         pn.value("version"),
			HasRelativePath: rp != nil,
		}
		if rp != nil {
			p.Parent.RelativePath = rp.text
		}
		p.Declarations = append(p.Declarations, declarationFrom(pn, KindParent, false, ""))
	}

	collectModules(root, "", &p.Modules)
	collectProperties(root, "", p.Properties)
	collectDeclarations(root, "", false, &p.Declarations)

	return p, nil
}

func collectModules(n *node, profile string, out *[]string) {
	if m := n.child("modules"); m != nil {
		for _, c := range m.childrenNamed("module") {
			if c.text != "" {
				*out = append(*out, c.text)
			}
		}
	}
	// Profile-scoped <modules> are real modules; a build that activates the
	// profile sees them, so they must be searched for declarations too.
	if profile == "" {
		if profiles := n.child("profiles"); profiles != nil {
			for _, pr := range profiles.childrenNamed("profile") {
				collectModules(pr, pr.value("id"), out)
			}
		}
	}
}

func collectProperties(n *node, profile string, out map[string]Property) {
	if props := n.child("properties"); props != nil {
		for _, c := range props.children {
			if c.textSpan.Empty() {
				continue
			}
			// A property declared at project level wins over a profile's,
			// because an inactive profile must not redirect the edit.
			if existing, ok := out[c.name]; ok && existing.Profile == "" {
				continue
			}
			out[c.name] = Property{
				Name:    c.name,
				Value:   c.text,
				Span:    c.textSpan,
				Profile: profile,
			}
		}
	}
	if profile == "" {
		if profiles := n.child("profiles"); profiles != nil {
			for _, pr := range profiles.childrenNamed("profile") {
				collectProperties(pr, pr.value("id"), out)
			}
		}
	}
}

// collectDeclarations walks the whole document. Declarations are found
// wherever they appear -- under <project>, <dependencyManagement>,
// <pluginManagement>, a <profile>, or nested inside another <plugin> -- which
// is what Maven itself does.
func collectDeclarations(n *node, profile string, managed bool, out *[]Declaration) {
	for _, c := range n.children {
		childManaged := managed
		childProfile := profile

		switch c.name {
		case "dependencyManagement", "pluginManagement":
			childManaged = true
		case "profile":
			childProfile = c.value("id")
		case "dependency":
			*out = append(*out, declarationFrom(c, KindDependency, managed, profile))
		case "plugin":
			*out = append(*out, declarationFrom(c, KindPlugin, managed, profile))
		case "extension":
			*out = append(*out, declarationFrom(c, KindExtension, managed, profile))
		case "path":
			*out = append(*out, declarationFrom(c, KindPath, managed, profile))
		case "parent":
			// Handled by Parse for the top-level parent; skip here so it is
			// not recorded twice.
			continue
		}

		collectDeclarations(c, childProfile, childManaged, out)
	}
}

func declarationFrom(n *node, kind Kind, managed bool, profile string) Declaration {
	d := Declaration{
		Kind:       kind,
		GroupID:    n.value("groupId"),
		ArtifactID: n.value("artifactId"),
		Classifier: n.value("classifier"),
		Type:       n.value("type"),
		Scope:      n.value("scope"),
		Managed:    managed,
		Profile:    profile,
	}

	if d.GroupID == "" && kind == KindPlugin {
		d.GroupID = DefaultPluginGroupID
	}
	switch {
	case kind == KindParent:
		d.Type = "pom"
	case d.Type == "":
		d.Type = "jar"
	}

	if v := n.child("version"); v != nil && !v.textSpan.Empty() {
		d.Version = v.text
		d.VersionSpan = v.textSpan
	}
	return d
}

// PropertyRef returns the property name when s is exactly one placeholder,
// e.g. "${jackson.version}". A version that merely contains a placeholder,
// such as "${base}.1" or "${a}-${b}", returns ok=false: those cannot be
// rewritten by replacing a single property value.
func PropertyRef(s string) (name string, ok bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") {
		return "", false
	}
	inner := s[2 : len(s)-1]
	if inner == "" || strings.ContainsAny(inner, "${}") {
		return "", false
	}
	return strings.TrimSpace(inner), true
}
