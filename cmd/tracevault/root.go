// Package tracevault provides the CLI commands for TraceVault.
package tracevault

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Set via ldflags
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "tracevault",
	Short: "Compliance automation without infrastructure access",
	Long: `TraceVault CLI - Evidence without Access

TraceVault enables organizations to achieve SOC 2, ISO 27001, and HIPAA
readiness without granting third-party vendors access to their production
infrastructure.

Run 'tracevault check' to evaluate your infrastructure against compliance
policies and generate evidence.`,
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("tracevault %s\n", version)
		fmt.Printf("  commit:  %s\n", commit)
		fmt.Printf("  built:   %s\n", buildTime)
	},
}

// setupCommands registers all commands with the root command.
func setupCommands() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(checkCmd)
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	setupCommands()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// SetVersionInfo sets version info from main package ldflags
func SetVersionInfo(v, c, b string) {
	version = v
	commit = c
	buildTime = b
}
