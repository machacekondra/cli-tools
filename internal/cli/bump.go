package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/project-lightpath/cli-tools/internal/maven"
)

type bumpOpts struct {
	repo         string
	pkg          string
	to           string
	from         string
	pin          bool
	dryRun       bool
	asJSON       bool
	noMatch      bool
	allowSkipped bool
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
		// Environment binding must happen in PreRunE: cobra checks required
		// flags after PreRunE but before RunE, so binding in RunE made
		// --package and --to impossible to supply via PACKAGE/FIXED_VERSION.
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return bindEnv(cmd, map[string]string{
				"repo":    "REPO_PATH",
				"package": "PACKAGE",
				"to":      "FIXED_VERSION",
				"from":    "CURRENT_VERSION",
			})
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
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
		"exit 0 when the package is not declared at all, instead of the default non-zero")
	f.BoolVar(&o.allowSkipped, "allow-skipped", false,
		"exit 0 even when a matching declaration was found but refused (a range, drift, or an unrewritable value)")

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
		if err := writeAll(o.repo, proj, updated); err != nil {
			return err
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

	// A declaration we refused to rewrite leaves the artifact vulnerable
	// through that module, even when other modules were updated. Exiting
	// zero there would let a pipeline treat a partial remediation as a
	// complete one.
	//
	// --allow-no-match deliberately does not suppress this. "Nothing matched"
	// and "we found it and refused" are different outcomes, and a flag that
	// forgives the first must not quietly forgive the second.
	if len(plan.Skipped) > 0 && !o.allowSkipped {
		return fmt.Errorf("%d declaration(s) of %s could not be updated; see the skipped entries above",
			len(plan.Skipped), o.pkg)
	}

	// Finding nothing is the dangerous outcome for a security remediation:
	// the pipeline would open a PR that fixes nothing. Fail unless asked not
	// to. Finding it already at the target version is a success.
	//
	// This only applies when nothing matched. If a declaration was found and
	// refused, that is the skip guard's business above -- reporting "nothing
	// to change" there would be wrong, and would mean --allow-skipped could
	// never produce a zero exit on its own.
	if len(plan.Skipped) == 0 && len(plan.Edits) == 0 && !plan.AlreadySatisfied && !o.noMatch {
		return fmt.Errorf("nothing to change for %s", o.pkg)
	}
	return nil
}

// writeAll stages every rewritten POM beside its original and renames it into
// place only once all of them are written.
//
// A plain WriteFile truncates before it writes, so a failure partway through
// the set leaves one POM half-written. The next run would then fail to parse
// the repository at all, turning a recoverable error into a broken checkout.
// Staging first means a failure leaves every original intact.
func writeAll(repo string, proj *maven.Project, updated map[string][]byte) error {
	type staged struct {
		tmp, dst, path string
		original       []byte
	}
	var ready []staged

	// A single deferred cleanup covers every return path. Removing only the
	// temp file of the step that failed left the ones staged after it behind.
	defer func() {
		for _, s := range ready {
			_ = os.Remove(s.tmp)
		}
	}()

	for path, content := range updated {
		dst := filepath.Join(repo, filepath.FromSlash(path))

		// Lstat, not Stat: a POM that is a symlink must not be replaced.
		// os.Rename swaps the directory entry, so it would turn the link
		// into an independent file and leave the POM it pointed at -- the
		// one actually read and planned against -- untouched, while the
		// command reported success.
		info, err := os.Lstat(dst)
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to replace it, as that would "+
				"detach the link from the POM it points at", path)
		}

		pom := proj.Pom(path)
		if pom == nil {
			return fmt.Errorf("internal error: no loaded POM for %s", path)
		}

		// The plan was computed from the bytes read at load time. If the file
		// has changed since, those offsets describe a file that no longer
		// exists and writing would discard someone else's edit.
		if err := checkUnchanged(dst, path, pom.Content); err != nil {
			return err
		}

		tmp, err := os.CreateTemp(filepath.Dir(dst), ".tssc-bump-*")
		if err != nil {
			return fmt.Errorf("staging %s: %w", path, err)
		}
		_, writeErr := tmp.Write(content)
		closeErr := tmp.Close()
		if writeErr == nil {
			writeErr = closeErr
		}
		if writeErr == nil {
			writeErr = os.Chmod(tmp.Name(), info.Mode().Perm())
		}
		if writeErr != nil {
			_ = os.Remove(tmp.Name())
			return fmt.Errorf("staging %s: %w", path, writeErr)
		}
		ready = append(ready, staged{tmp: tmp.Name(), dst: dst, path: path, original: pom.Content})
	}

	// Renames are the only destructive step, and each is atomic. One can
	// still fail after an earlier one succeeded, so say which files landed
	// rather than leaving the caller to guess.
	var done []string
	for i, s := range ready {
		// Re-check here, not just at staging time: staging every other file
		// and renaming the earlier ones all happen in between. This narrows
		// the window rather than closing it -- without a lock or a
		// conditional rename, a write landing between this check and the
		// rename below is still lost.
		if err := checkUnchanged(s.dst, s.path, s.original); err != nil {
			return err
		}
		if err := os.Rename(s.tmp, s.dst); err != nil {
			return fmt.Errorf("replacing %s: %w (already updated: %v)", s.dst, err, done)
		}
		ready[i].tmp = "" // renamed away; nothing left to clean up
		done = append(done, s.dst)
	}
	return nil
}

// checkUnchanged fails if the file no longer holds the bytes the plan was
// built from.
func checkUnchanged(dst, path string, original []byte) error {
	current, err := os.ReadFile(dst)
	if err != nil {
		return fmt.Errorf("re-reading %s: %w", path, err)
	}
	if !bytes.Equal(current, original) {
		return fmt.Errorf("%s changed on disk after it was read; re-run the command", path)
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

	// Collect the first write error rather than ignoring every one: a report
	// that silently vanished because stdout was a closed pipe must not look
	// like a successful run.
	var writeErr error
	line := func(format string, args ...any) {
		if writeErr != nil {
			return
		}
		if _, err := fmt.Fprintf(out, format, args...); err != nil {
			writeErr = err
		}
	}

	switch {
	case res.AlreadySatisfied:
		line("no change: %s is already at %s\n", res.Package, res.Version)
	case len(res.Changed) == 0 && len(res.Skipped) > 0:
		// It was found; we declined to rewrite it. The per-skip lines below
		// say why, so do not also claim it is undeclared.
		line("no change: %s was found but not rewritten\n", res.Package)
	case len(res.Changed) == 0:
		line("no change: %s is not declared in this repository\n", res.Package)
	}
	for _, c := range res.Changed {
		prefix := "updated"
		if o.dryRun {
			prefix = "would update"
		}
		line("%s %s: %s\n", prefix, c.File, c.Description)
	}
	for _, s := range res.Shared {
		line("\nnote: property %s in %s also sets the version of:\n", s.Property, s.File)
		for _, c := range s.AlsoAffects {
			line("  - %s\n", c)
		}
	}
	for _, s := range res.Skipped {
		line("skipped %s: %s\n", s.File, s.Reason)
	}
	return writeErr
}
