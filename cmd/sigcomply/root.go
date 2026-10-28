// Package cmd is the CLI entry. Subcommands shipped: check, version,
// init, init-ci, build, report.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// backendLocal is the "local" backend identifier, shared by the
// filesystem vault backend and the manual-evidence reader backend.
const backendLocal = "local"

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
	return exitCodeFor(newRootCmd().Execute(), os.Stderr)
}

// exitCodeFor maps a command error to the process exit code and prints
// it. The root command sets SilenceErrors, so this is the single
// top-level "Error: ..." print. An exitCodeError anywhere in the chain
// stamps the code, else 2. A bare exitCodeError (code only, no wrapped
// error) is a normal non-OK exit such as a policy violation: no
// message, just the code.
func exitCodeFor(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	code := 2
	var e *exitCodeError
	if errors.As(err, &e) {
		code = e.code
		if err == error(e) && e.err == nil {
			return code
		}
	}
	_, _ = fmt.Fprintln(stderr, "Error:", err) //nolint:errcheck // nothing useful to do on stderr write failure
	return code
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sigcomply",
		Short: "SigComply — zero-trust, non-custodial compliance engine",
		Long: "SigComply runs in your CI/CD environment, evaluates Go-native compliance\n" +
			"policies (a declarative pass_when DSL) against infrastructure and uploaded\n" +
			"evidence, signs the resulting evidence locally, and\n" +
			"optionally submits aggregated counts to a private cloud dashboard.\n",
		// Don't dump the ~19-line usage/flags block after an error (a
		// missing config, a bad framework); the one-line message is what
		// the operator needs. Cobra applies the root's SilenceUsage to
		// every subcommand, so a flag-parse error also prints one line
		// ("Error: unknown flag: --x", exit 2); `--help` still prints
		// usage. SilenceErrors lets Execute() own the single top-level
		// "Error: ..." print (see Execute).
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newCheckCmd())
	root.AddCommand(newInitCmd())
	root.AddCommand(newInitCICmd())
	root.AddCommand(newBuildCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newEvidenceCmd())
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
