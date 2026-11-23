// Command tssc is the single entrypoint for the TSSC pipeline tools.
//
// Subcommands (tssc rhtpa analyze, tssc ai analyze-cves, ...) replace the
// inline scripts that used to live in the Tekton Tasks. One binary keeps the
// container image to a single copy of the dependency tree; the image also
// installs argv[0] symlinks so a Task can invoke rhtpa-analyze directly.
package main

import (
	"fmt"
	"os"

	"github.com/project-lightpath/cli-tools/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
