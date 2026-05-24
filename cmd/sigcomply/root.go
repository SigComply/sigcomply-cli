// Package cmd is the CLI entry. Subcommands shipped: check, version,
// init-ci, build, report.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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

// Execute is the CLI entrypoint. Returns the recommended exit code so
// main can pass it to os.Exit; tests can call Execute directly.
func Execute() int {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		// Cobra already printed the error; honor any RunResult exit
		// code stamped via ExitCodeError, else default to 2.
		if e, ok := err.(*exitCodeError); ok {
			return e.code
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sigcomply",
		Short: "SigComply — zero-trust, non-custodial compliance engine",
		Long: "SigComply runs in your CI/CD environment, evaluates OPA/Rego policies against\n" +
			"infrastructure and uploaded evidence, signs the resulting evidence locally, and\n" +
			"optionally submits aggregated counts to a private cloud dashboard.\n",
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newCheckCmd())
	root.AddCommand(newInitCICmd())
	root.AddCommand(newBuildCmd())
	root.AddCommand(newReportCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print CLI version, commit, and build time",
		Run: func(cmd *cobra.Command, _ []string) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "sigcomply %s (commit %s, built %s)\n", cliVersion, cliCommit, cliBuildTime) //nolint:errcheck // status output; nothing useful to do on failure
		},
	}
}

// exitCodeError carries a non-zero exit code back through cobra's error
// path so Execute can recover it.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (e *exitCodeError) Unwrap() error { return e.err }
