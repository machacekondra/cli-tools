// Package version carries build metadata stamped in by the linker.
package version

import "runtime/debug"

// Set via -ldflags at build time; see the Makefile.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// String renders a one-line version banner.
func String() string {
	v := Version
	if Commit == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					Commit = s.Value
				}
			}
		}
	}
	if Commit != "" {
		v += " (" + Commit + ")"
	}
	if Date != "" {
		v += " built " + Date
	}
	return v
}
