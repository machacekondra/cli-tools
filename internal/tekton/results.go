// Package tekton handles the bits of the Tekton contract the tools need:
// writing results, and trusting the pipeline's CA bundle.
//
// Everything here degrades to a no-op outside a TaskRun, so the same binary
// runs on a laptop against a saved SBOM with no special flags.
package tekton

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultResultsDir is where Tekton mounts the result files.
const DefaultResultsDir = "/tekton/results"

// CABundlePath is the CA bundle the surrounding pipeline may provide.
const CABundlePath = "/tekton-custom-certs/ca-bundle.crt"

// Results writes Tekton task results. The zero value is unusable; call
// NewResults.
type Results struct {
	dir string
}

// NewResults returns a Results writing to dir. An empty dir selects
// DefaultResultsDir when it exists, and otherwise disables writing so the
// command still runs outside Tekton.
func NewResults(dir string) *Results {
	if dir == "" {
		if _, err := os.Stat(DefaultResultsDir); err == nil {
			dir = DefaultResultsDir
		}
	}
	return &Results{dir: dir}
}

// Enabled reports whether results will actually be written.
func (r *Results) Enabled() bool { return r.dir != "" }

// Write records a single result. Writing is best-effort only in the sense that
// it is skipped outside Tekton; inside Tekton a failure is returned, because a
// task whose results never landed has silently broken the pipeline downstream.
func (r *Results) Write(name, value string) error {
	if !r.Enabled() {
		return nil
	}
	path := filepath.Join(r.dir, name)
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("writing Tekton result %s: %w", name, err)
	}
	return nil
}

// WriteAll records several results, stopping at the first failure.
func (r *Results) WriteAll(kv map[string]string) error {
	for name, value := range kv {
		if err := r.Write(name, value); err != nil {
			return err
		}
	}
	return nil
}
