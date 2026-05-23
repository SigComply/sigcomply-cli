// Package cmd is the CLI entry. At M0 it is a placeholder: subcommands
// (check, evidence, report, init-ci, …) are wired in later milestones
// per docs/architecture/09-implementation-roadmap.md.
package cmd

import (
	"fmt"
	"os"
)

var (
	cliVersion   = "dev"
	cliCommit    = "unknown"
	cliBuildTime = "unknown"
)

// SetVersionInfo stores ldflag-injected build identity for later display.
func SetVersionInfo(version, commit, buildTime string) {
	cliVersion = version
	cliCommit = commit
	cliBuildTime = buildTime
}

// Execute is the CLI entrypoint. At M0 it prints version info and exits;
// command wiring arrives at M12 (orchestrator).
func Execute() {
	fmt.Fprintf(os.Stderr,
		"sigcomply %s (commit %s, built %s)\n"+
			"M0 skeleton — commands not yet wired (see docs/architecture/09-implementation-roadmap.md).\n",
		cliVersion, cliCommit, cliBuildTime)
}
