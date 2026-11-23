package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/project-lightpath/cli-tools/internal/maven"
)

type bumpOpts struct {
	repo    string
	pkg     string
	to      string
	from    string
	pin     bool
	dryRun  bool
	asJSON  bool
	noMatch bool
}

func newBumpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bump",
		Short: "Rewrite a dependency version in a repository",
	}
	cmd.AddCommand(newBumpMavenCmd())
	return cmd
}

func newBumpMavenCmd() *cobra.Command {
	var o bumpOpts

	cmd := &cobra.Command{
		Use:   "maven",
		Short: "Bump a Maven dependency to a given version",
		Long: `Rewrite a Maven dependency's version across a repository.

The coordinate and target version are inputs, not something this command
discovers: they come from a scanner such as RHTPA. No registry is contacted.

Edits are byte-range splices on the original POMs, so formatting, comments and
attribute order survive untouched. Where a version is declared through a
property the property is rewritten instead, in whichever POM declares it --
including a parent. If the artifact is not declared anywhere, which is the
usual case for an SBOM finding against a transitive dependency, a
dependencyManagement entry is added to pin it.

Nothing is rewritten silently: every declaration that matched but was
deliberately left alone is reported, as is every other artifact moved by a
shared property.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := bindEnv(cmd, map[string]string{
				"repo":    "REPO_PATH",
				"package": "PACKAGE",
				"to":      "FIXED_VERSION",
				"from":    "CURRENT_VERSION",
			}); err != nil {
				return err
			}
			return runBumpMaven(cmd, &o)
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.repo, "repo", ".", "path to the repository checkout")
	f.StringVarP(&o.pkg, "package", "p", "", "groupId:artifactId to bump (required)")
	f.StringVar(&o.to, "to", "", "version to set (required)")
	f.StringVar(&o.from, "from", "",
		"expected current version; when set, refuse to rewrite anything that does not currently hold it")
	f.BoolVar(&o.pin, "pin-transitive", true,
		"when the artifact is not declared anywhere, add a dependencyManagement entry pinning it")
	f.BoolVar(&o.dryRun, "dry-run", false, "report what would change without writing")
	f.BoolVar(&o.asJSON, "json", false, "emit the result as JSON")
	f.BoolVar(&o.noMatch, "allow-no-match", false,
		"exit 0 when nothing matched, instead of the default non-zero")

	_ = cmd.MarkFlagRequired("package")
	_ = cmd.MarkFlagRequired("to")

	return cmd
}

// result is the machine-readable form of a run.
type result struct {
	Package string   `json:"package"`
	Version string   `json:"version"`
	Changed []change `json:"changed"`
	Pinned  bool     `json:"pinned"`
	Shared  []shared `json:"shared_properties,omitempty"`
	Skipped []skip   `json:"skipped,omitempty"`
	DryRun  bool     `json:"dry_run"`

	// AlreadySatisfied distinguishes "the fix is already in place" from
	// "nothing matched", which look identical in the change list but mean
	// opposite things to a remediation pipeline.
	AlreadySatisfied bool `json:"already_satisfied"`
}

type change struct {
	File        string `json:"file"`
	Description string `json:"description"`
}

type shared struct {
	Property    string   `json:"property"`
	File        string   `json:"file"`
	AlsoAffects []string `json:"also_affects"`
}

type skip struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

func runBumpMaven(cmd *cobra.Command, o *bumpOpts) error {
	group, artifact, ok := strings.Cut(o.pkg, ":")
	if !ok || group == "" || artifact == "" {
		return fmt.Errorf("--package must be groupId:artifactId, got %q", o.pkg)
	}

	proj, err := maven.Load(o.repo)
	if err != nil {
		return err
	}

	plan, err := maven.BumpProject(proj, maven.Request{
		GroupID:        group,
		ArtifactID:     artifact,
		NewVersion:     o.to,
		CurrentVersion: o.from,
		PinIfMissing:   o.pin,
	})
	if err != nil {
		return err
	}

	updated, err := maven.Apply(proj, plan)
	if err != nil {
		return err
	}

	if !o.dryRun {
		for path, content := range updated {
			full := filepath.Join(o.repo, filepath.FromSlash(path))
			info, err := os.Stat(full)
			if err != nil {
				return fmt.Errorf("stat %s: %w", path, err)
			}
			if err := os.WriteFile(full, content, info.Mode().Perm()); err != nil {
				return fmt.Errorf("writing %s: %w", path, err)
			}
		}
	}

	res := result{
		Package:          o.pkg,
		Version:          o.to,
		Pinned:           plan.Pinned,
		AlreadySatisfied: plan.AlreadySatisfied,
		DryRun:           o.dryRun,
	}
	for _, e := range plan.Edits {
		res.Changed = append(res.Changed, change{File: e.Path, Description: e.Description})
	}
	for _, s := range plan.SharedProperties {
		res.Shared = append(res.Shared, shared{Property: s.Name, File: s.Pom, AlsoAffects: s.AlsoAffects})
	}
	for _, s := range plan.Skipped {
		res.Skipped = append(res.Skipped, skip{File: s.Pom, Reason: s.Reason})
	}

	if err := report(cmd, o, res); err != nil {
		return err
	}

	// Finding nothing is the dangerous outcome for a security remediation:
	// the pipeline would open a PR that fixes nothing. Fail unless asked not
	// to. Finding it already at the target version is a success.
	if len(plan.Edits) == 0 && !plan.AlreadySatisfied && !o.noMatch {
		return fmt.Errorf("nothing to change for %s", o.pkg)
	}
	return nil
}

func report(cmd *cobra.Command, o *bumpOpts, res result) error {
	out := cmd.OutOrStdout()

	if o.asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	switch {
	case res.AlreadySatisfied:
		fmt.Fprintf(out, "no change: %s is already at %s\n", res.Package, res.Version)
	case len(res.Changed) == 0 && len(res.Skipped) > 0:
		// It was found; we declined to rewrite it. The per-skip lines below
		// say why, so do not also claim it is undeclared.
		fmt.Fprintf(out, "no change: %s was found but not rewritten\n", res.Package)
	case len(res.Changed) == 0:
		fmt.Fprintf(out, "no change: %s is not declared in this repository\n", res.Package)
	}
	for _, c := range res.Changed {
		prefix := "updated"
		if o.dryRun {
			prefix = "would update"
		}
		fmt.Fprintf(out, "%s %s: %s\n", prefix, c.File, c.Description)
	}
	for _, s := range res.Shared {
		fmt.Fprintf(out, "\nnote: property %s in %s also sets the version of:\n", s.Property, s.File)
		for _, c := range s.AlsoAffects {
			fmt.Fprintf(out, "  - %s\n", c)
		}
	}
	for _, s := range res.Skipped {
		fmt.Fprintf(out, "skipped %s: %s\n", s.File, s.Reason)
	}
	return nil
}
