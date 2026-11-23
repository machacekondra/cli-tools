package maven

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The cases here are drawn from the behaviours dependabot-core and Renovate
// each carry regression tests for. They are the ones a naive find-and-replace
// gets wrong.

func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for path, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// run plans and applies a bump, returning the plan and the updated files.
func run(t *testing.T, files map[string]string, req Request) (*Plan, map[string]string) {
	t.Helper()
	proj, err := Load(writeRepo(t, files))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	plan, err := BumpProject(proj, req)
	if err != nil {
		t.Fatalf("BumpProject: %v", err)
	}
	applied, err := Apply(proj, plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out := map[string]string{}
	for k, v := range applied {
		out[k] = string(v)
	}
	return plan, out
}

func pom(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
` + body + `
</project>
`
}

func jackson(v string) Request {
	return Request{
		GroupID:    "com.fasterxml.jackson.core",
		ArtifactID: "jackson-databind",
		NewVersion: v,
	}
}

func TestDirectVersionBump(t *testing.T) {
	src := pom(`  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.13.0</version>
    </dependency>
  </dependencies>`)

	_, out := run(t, map[string]string{"pom.xml": src}, jackson("2.15.4"))

	got := out["pom.xml"]
	if !strings.Contains(got, "<version>2.15.4</version>") {
		t.Errorf("version not bumped:\n%s", got)
	}
	// Only the dependency version may change; the project's own must not.
	if !strings.Contains(got, "<version>1.0.0</version>") {
		t.Error("project version was clobbered")
	}
	if strings.Contains(got, "2.13.0") {
		t.Error("old version still present")
	}
	if diff := len(strings.Split(got, "\n")) - len(strings.Split(src, "\n")); diff != 0 {
		t.Errorf("line count changed by %d; formatting was not preserved", diff)
	}
}

func TestPreservesSurroundingWhitespaceAndComments(t *testing.T) {
	tests := []struct {
		name string
		decl string
		want string
	}{
		{
			name: "padding inside the element",
			decl: "<version>  2.13.0  </version>",
			want: "<version>  2.15.4  </version>",
		},
		{
			name: "trailing comment inside the element",
			decl: "<version>2.13.0<!-- pinned by security --></version>",
			want: "<version>2.15.4<!-- pinned by security --></version>",
		},
		{
			name: "leading comment inside the element",
			decl: "<version><!-- pinned -->2.13.0</version>",
			want: "<version><!-- pinned -->2.15.4</version>",
		},
		{
			name: "value on its own line",
			decl: "<version>\n        2.13.0\n      </version>",
			want: "<version>\n        2.15.4\n      </version>",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := pom(`  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      ` + tc.decl + `
    </dependency>
  </dependencies>`)

			_, out := run(t, map[string]string{"pom.xml": src}, jackson("2.15.4"))
			if !strings.Contains(out["pom.xml"], tc.want) {
				t.Errorf("want %q in output:\n%s", tc.want, out["pom.xml"])
			}
		})
	}
}

// A plugin's <configuration> can repeat the same version text. Only the
// declaration's own direct <version> child may be rewritten.
func TestIgnoresVersionInsidePluginConfiguration(t *testing.T) {
	src := pom(`  <build>
    <plugins>
      <plugin>
        <artifactId>maven-enforcer-plugin</artifactId>
        <version>3.0.0</version>
        <configuration>
          <rules>
            <requireMavenVersion>
              <version>3.0.0</version>
            </requireMavenVersion>
          </rules>
        </configuration>
      </plugin>
    </plugins>
  </build>`)

	_, out := run(t, map[string]string{"pom.xml": src}, Request{
		// groupId omitted in the POM, so it defaults to the Maven plugin group.
		GroupID:    DefaultPluginGroupID,
		ArtifactID: "maven-enforcer-plugin",
		NewVersion: "3.4.1",
	})

	got := out["pom.xml"]
	if !strings.Contains(got, "<version>3.4.1</version>") {
		t.Errorf("plugin version not bumped:\n%s", got)
	}
	if !strings.Contains(got, "<requireMavenVersion>\n              <version>3.0.0</version>") {
		t.Errorf("configuration version was rewritten; it must not be:\n%s", got)
	}
}

func TestPropertyIndirection(t *testing.T) {
	src := pom(`  <properties>
    <jackson.version>2.13.0</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>`)

	plan, out := run(t, map[string]string{"pom.xml": src}, jackson("2.15.4"))

	got := out["pom.xml"]
	if !strings.Contains(got, "<jackson.version>2.15.4</jackson.version>") {
		t.Errorf("property not bumped:\n%s", got)
	}
	if !strings.Contains(got, "<version>${jackson.version}</version>") {
		t.Error("the placeholder at the call site must be left alone")
	}
	if len(plan.SharedProperties) != 0 {
		t.Errorf("property backs only this artifact, want no shared-property report, got %+v", plan.SharedProperties)
	}
}

// The property may be declared in a parent POM; the edit has to land there.
func TestPropertyInParentPom(t *testing.T) {
	parent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <properties>
    <jackson.version>2.13.0</jackson.version>
  </properties>
  <modules>
    <module>child</module>
  </modules>
</project>
`
	child := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>
</project>
`
	plan, out := run(t, map[string]string{
		"pom.xml":       parent,
		"child/pom.xml": child,
	}, jackson("2.15.4"))

	if _, touched := out["child/pom.xml"]; touched {
		t.Error("child POM must not be modified; the property lives in the parent")
	}
	if !strings.Contains(out["pom.xml"], "<jackson.version>2.15.4</jackson.version>") {
		t.Errorf("parent property not bumped:\n%s", out["pom.xml"])
	}
	if len(plan.Edits) != 1 {
		t.Errorf("want exactly one edit, got %d: %+v", len(plan.Edits), plan.Edits)
	}
}

func TestSharedPropertyReportsBlastRadius(t *testing.T) {
	src := pom(`  <properties>
    <jackson.version>2.13.0</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-core</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>`)

	plan, out := run(t, map[string]string{"pom.xml": src}, jackson("2.15.4"))

	if !strings.Contains(out["pom.xml"], "<jackson.version>2.15.4</jackson.version>") {
		t.Error("property not bumped")
	}
	if len(plan.SharedProperties) != 1 {
		t.Fatalf("want one shared-property report, got %+v", plan.SharedProperties)
	}
	got := plan.SharedProperties[0]
	if len(got.AlsoAffects) != 1 || got.AlsoAffects[0] != "com.fasterxml.jackson.core:jackson-core" {
		t.Errorf("want jackson-core reported as also affected, got %v", got.AlsoAffects)
	}
}

func TestMultiModuleBumpsEveryDeclaration(t *testing.T) {
	root := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>root</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <modules>
    <module>a</module>
    <module>b</module>
  </modules>
</project>
`
	mod := func(name string) string {
		return `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>` + name + `</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.13.0</version>
    </dependency>
  </dependencies>
</project>
`
	}

	plan, out := run(t, map[string]string{
		"pom.xml":   root,
		"a/pom.xml": mod("a"),
		"b/pom.xml": mod("b"),
	}, jackson("2.15.4"))

	if len(plan.Edits) != 2 {
		t.Fatalf("want 2 edits (one per module), got %d: %+v", len(plan.Edits), plan.Edits)
	}
	for _, p := range []string{"a/pom.xml", "b/pom.xml"} {
		if !strings.Contains(out[p], "<version>2.15.4</version>") {
			t.Errorf("%s not bumped:\n%s", p, out[p])
		}
	}
}

func TestRefusals(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		req        Request
		wantReason string
	}{
		{
			name:       "version range",
			version:    "[2.13.0,2.14.0)",
			req:        jackson("2.15.4"),
			wantReason: "range",
		},
		{
			name:       "property interpolated into a larger string",
			version:    "${jackson.base}.1",
			req:        jackson("2.15.4"),
			wantReason: "interpolates",
		},
		{
			name:    "drift: on-disk version is not what the caller expected",
			version: "2.14.0",
			req: Request{
				GroupID:        "com.fasterxml.jackson.core",
				ArtifactID:     "jackson-databind",
				NewVersion:     "2.15.4",
				CurrentVersion: "2.13.0",
			},
			wantReason: "refusing to overwrite",
		},
		{
			name:       "property declared nowhere in the repo",
			version:    "${from.remote.parent}",
			req:        jackson("2.15.4"),
			wantReason: "not declared in this repository",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := pom(`  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>` + tc.version + `</version>
    </dependency>
  </dependencies>`)

			plan, out := run(t, map[string]string{"pom.xml": src}, tc.req)

			if len(plan.Edits) != 0 {
				t.Errorf("want no edits, got %+v", plan.Edits)
			}
			if len(out) != 0 {
				t.Error("no file should have been rewritten")
			}
			if len(plan.Skipped) != 1 {
				t.Fatalf("want one skip explaining the refusal, got %+v", plan.Skipped)
			}
			if !strings.Contains(plan.Skipped[0].Reason, tc.wantReason) {
				t.Errorf("reason %q does not mention %q", plan.Skipped[0].Reason, tc.wantReason)
			}
		})
	}
}

// Re-running a completed bump must be a clean no-op, not a corruption.
func TestIdempotent(t *testing.T) {
	src := pom(`  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.4</version>
    </dependency>
  </dependencies>`)

	plan, out := run(t, map[string]string{"pom.xml": src}, jackson("2.15.4"))
	if !plan.Empty() {
		t.Errorf("want no edits when already at target, got %+v", plan.Edits)
	}
	if len(out) != 0 {
		t.Error("no file should have been rewritten")
	}
}

// Regression: re-running a completed bump with pinning enabled must not add a
// dependencyManagement entry. "Already at the target" produces no edit and no
// skip, which previously looked identical to "not declared at all", so every
// re-run appended another redundant pin.
func TestIdempotentWithPinningEnabled(t *testing.T) {
	cases := map[string]string{
		"direct version": `  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.4</version>
    </dependency>
  </dependencies>`,
		"via property": `  <properties>
    <jackson.version>2.15.4</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := jackson("2.15.4")
			req.PinIfMissing = true

			plan, out := run(t, map[string]string{"pom.xml": pom(body)}, req)

			if plan.Pinned {
				t.Error("must not pin an artifact that is already declared at the target version")
			}
			if !plan.Empty() {
				t.Errorf("want no edits, got %+v", plan.Edits)
			}
			if !plan.AlreadySatisfied {
				t.Error("want AlreadySatisfied so the caller can tell this from 'nothing matched'")
			}
			if len(out) != 0 {
				t.Error("no file should have been rewritten")
			}
		})
	}
}

// A refusal must not fall through to pinning: adding a dependencyManagement
// entry would override the very range or drifted value we declined to touch.
func TestRefusalDoesNotFallBackToPinning(t *testing.T) {
	src := pom(`  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>[2.13.0,2.14.0)</version>
    </dependency>
  </dependencies>`)

	req := jackson("2.15.4")
	req.PinIfMissing = true
	plan, out := run(t, map[string]string{"pom.xml": src}, req)

	if plan.Pinned {
		t.Error("a refused declaration must not be silently overridden by a pin")
	}
	if len(out) != 0 {
		t.Error("no file should have been rewritten")
	}
}

func TestPinTransitiveCreatesDependencyManagement(t *testing.T) {
	src := pom(`  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
      <version>5.3.0</version>
    </dependency>
  </dependencies>`)

	req := jackson("2.15.4")
	req.PinIfMissing = true
	plan, out := run(t, map[string]string{"pom.xml": src}, req)

	if !plan.Pinned {
		t.Fatal("want Pinned set for an undeclared artifact")
	}
	got := out["pom.xml"]
	want := `  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.15.4</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
`
	if !strings.Contains(got, want) {
		t.Errorf("generated block not found.\nwant:\n%s\ngot:\n%s", want, got)
	}
	// The result must still parse, and must now resolve the artifact.
	assertReparses(t, got, "com.fasterxml.jackson.core:jackson-databind", "2.15.4")
}

func TestPinTransitiveAppendsToExistingDependencyManagement(t *testing.T) {
	src := pom(`  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-web</artifactId>
        <version>5.3.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>`)

	req := jackson("2.15.4")
	req.PinIfMissing = true
	_, out := run(t, map[string]string{"pom.xml": src}, req)

	got := out["pom.xml"]
	if strings.Count(got, "<dependencyManagement>") != 1 {
		t.Errorf("want the existing dependencyManagement reused, got:\n%s", got)
	}
	if !strings.Contains(got, "<artifactId>spring-web</artifactId>") {
		t.Error("existing entry was lost")
	}
	assertReparses(t, got, "com.fasterxml.jackson.core:jackson-databind", "2.15.4")
}

func TestPinUsesTheFilesOwnIndentation(t *testing.T) {
	src := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n" +
		"\t<groupId>com.example</groupId>\n" +
		"\t<artifactId>app</artifactId>\n" +
		"\t<version>1.0.0</version>\n" +
		"</project>\n"

	req := jackson("2.15.4")
	req.PinIfMissing = true
	_, out := run(t, map[string]string{"pom.xml": src}, req)

	got := out["pom.xml"]
	if !strings.Contains(got, "\t<dependencyManagement>") {
		t.Errorf("want tab indentation to be matched, got:\n%s", got)
	}
	if strings.Contains(got, "  <dependencyManagement>") {
		t.Error("two-space indentation was used in a tab-indented file")
	}
}

// An empty <relativePath/> means "resolve from the repository, not from
// disk". Treating it as absent defaults it to ../pom.xml, which in a flat
// layout makes a POM its own parent.
func TestEmptyRelativePathIsNotTreatedAsDefault(t *testing.T) {
	src := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.1.0</version>
    <relativePath/>
  </parent>
  <artifactId>app</artifactId>
</project>
`
	proj, err := Load(writeRepo(t, map[string]string{"pom.xml": src}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(proj.Poms); got != 1 {
		t.Fatalf("want exactly 1 POM loaded, got %d", got)
	}
	// The chain must terminate rather than loop through itself.
	if got := len(proj.ancestors(proj.Pom("pom.xml"))); got != 1 {
		t.Errorf("want ancestor chain of length 1, got %d", got)
	}
}

// A profile's <properties> only applies when that profile is active, so a
// project-level declaration of the same name must win. Editing the profile
// copy would leave the default build on the vulnerable version.
func TestProjectPropertyWinsOverProfileProperty(t *testing.T) {
	src := pom(`  <properties>
    <jackson.version>2.13.0</jackson.version>
  </properties>
  <profiles>
    <profile>
      <id>legacy</id>
      <properties>
        <jackson.version>2.9.0</jackson.version>
      </properties>
    </profile>
  </profiles>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>`)

	plan, out := run(t, map[string]string{"pom.xml": src}, jackson("2.15.4"))

	if len(plan.Edits) != 1 {
		t.Fatalf("want exactly 1 edit, got %d: %+v", len(plan.Edits), plan.Edits)
	}
	got := out["pom.xml"]
	if !strings.Contains(got, "<jackson.version>2.15.4</jackson.version>") {
		t.Errorf("project-level property not bumped:\n%s", got)
	}
	if !strings.Contains(got, "<jackson.version>2.9.0</jackson.version>") {
		t.Errorf("the profile's property must be left alone:\n%s", got)
	}
}

// With no project-level declaration, the profile's property is the only
// definition there is, so it should be used.
func TestProfilePropertyUsedWhenItIsTheOnlyOne(t *testing.T) {
	src := pom(`  <profiles>
    <profile>
      <id>legacy</id>
      <properties>
        <jackson.version>2.13.0</jackson.version>
      </properties>
    </profile>
  </profiles>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>`)

	_, out := run(t, map[string]string{"pom.xml": src}, jackson("2.15.4"))
	if !strings.Contains(out["pom.xml"], "<jackson.version>2.15.4</jackson.version>") {
		t.Errorf("profile property not bumped:\n%s", out["pom.xml"])
	}
}

// A dependency whose version comes from dependencyManagement has no <version>
// of its own. It must be skipped silently, with the managed entry carrying
// the edit -- not reported as an unresolvable failure.
func TestVersionlessDeclarationDefersToManagedEntry(t *testing.T) {
	src := pom(`  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.13.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>`)

	plan, out := run(t, map[string]string{"pom.xml": src}, jackson("2.15.4"))

	if len(plan.Edits) != 1 {
		t.Fatalf("want exactly 1 edit (the managed entry), got %d: %+v", len(plan.Edits), plan.Edits)
	}
	if len(plan.Skipped) != 0 {
		t.Errorf("the versionless declaration must not be reported as a skip: %+v", plan.Skipped)
	}
	if n := strings.Count(out["pom.xml"], "2.15.4"); n != 1 {
		t.Errorf("want exactly one occurrence of the new version, got %d:\n%s", n, out["pom.xml"])
	}
}

func TestRecursivePropertyDoesNotHang(t *testing.T) {
	src := pom(`  <properties>
    <a.version>${b.version}</a.version>
    <b.version>${a.version}</b.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${a.version}</version>
    </dependency>
  </dependencies>`)

	proj, err := Load(writeRepo(t, map[string]string{"pom.xml": src}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := proj.resolveVersion(proj.Pom("pom.xml"), "${a.version}"); ok {
		t.Error("a cyclic property must not resolve")
	}
}

// Several edits in one file must all land; applying them in ascending order
// would invalidate later offsets once the first replacement changes length.
func TestMultipleEditsInOneFile(t *testing.T) {
	src := pom(`  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.13.0</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <classifier>tests</classifier>
      <version>2.13.0</version>
    </dependency>
  </dependencies>`)

	plan, out := run(t, map[string]string{"pom.xml": src}, jackson("2.15.4-with-a-much-longer-suffix"))

	if len(plan.Edits) != 2 {
		t.Fatalf("want 2 edits, got %d", len(plan.Edits))
	}
	got := out["pom.xml"]
	if n := strings.Count(got, "<version>2.15.4-with-a-much-longer-suffix</version>"); n != 2 {
		t.Errorf("want both declarations bumped, got %d:\n%s", n, got)
	}
	if strings.Contains(got, "2.13.0") {
		t.Errorf("an old version survived:\n%s", got)
	}
}

// assertReparses checks the rewritten content is still well-formed and that
// the named coordinate now carries the expected version.
func assertReparses(t *testing.T, content, coord, wantVersion string) {
	t.Helper()
	p, err := Parse("pom.xml", []byte(content))
	if err != nil {
		t.Fatalf("rewritten POM no longer parses: %v", err)
	}
	for _, d := range p.Declarations {
		if d.Coord() == coord {
			if d.Version != wantVersion {
				t.Errorf("want %s at %s, got %q", coord, wantVersion, d.Version)
			}
			return
		}
	}
	t.Errorf("%s not found in the rewritten POM", coord)
}
