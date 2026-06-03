package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/builtin" // side-effect: registers every in-tree framework factory
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
)

const (
	outputText = "text"
	outputJSON = "json"
)

// evidenceFlags carries the flags accepted by `sigcomply evidence`
// subcommands.
type evidenceFlags struct {
	framework string
	output    string
}

// newEvidenceCmd builds the `evidence` parent and its subcommands. Today
// only `catalog` is wired — it exports the descriptive manual-evidence
// catalog consumed by the Evidence SPA (scripts/fetch-catalogs.ts).
func newEvidenceCmd() *cobra.Command {
	var flags evidenceFlags
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Inspect manual-evidence requirements",
		Long: "Commands for working with the manual-evidence catalog. The catalog is\n" +
			"derived from the selected framework's manual policies and is consumed by\n" +
			"the optional Evidence SPA to render declaration/checklist forms.\n",
	}
	cmd.PersistentFlags().StringVarP(&flags.framework, "framework", "f", "",
		"Framework (defaults to $SIGCOMPLY_FRAMEWORK, then soc2)")
	cmd.PersistentFlags().StringVarP(&flags.output, "output", "o", outputText,
		"Output format: text | json")
	cmd.AddCommand(newEvidenceCatalogCmd(&flags))
	return cmd
}

func newEvidenceCatalogCmd(flags *evidenceFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "catalog",
		Short: "Print the manual-evidence catalog (text or JSON)",
		Long: "Prints the selected framework's manual-evidence catalog. With `-o json`\n" +
			"the output matches the Evidence SPA's Catalog contract\n" +
			"(framework, version, entries[]). Works without a project config.\n",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEvidenceCatalog(cmd.OutOrStdout(), flags)
		},
	}
}

// resolveFramework picks the framework from the flag, then the
// SIGCOMPLY_FRAMEWORK env var, then the soc2 default. The catalog
// command is standalone — it never requires a .sigcomply.yaml.
func resolveFramework(flag string) string {
	if flag != "" {
		return flag
	}
	if env := os.Getenv("SIGCOMPLY_FRAMEWORK"); env != "" {
		return env
	}
	return "soc2"
}

func runEvidenceCatalog(stdout io.Writer, flags *evidenceFlags) error {
	fwID := resolveFramework(flags.framework)
	factory, ok := frameworks.Lookup(fwID)
	if !ok {
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("evidence catalog: framework %q not supported (registered: %v)", fwID, frameworks.IDs())}
	}
	if factory.ManualCatalogExport == nil {
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("evidence catalog: framework %q has no manual catalog", fwID)}
	}
	cat := factory.ManualCatalogExport()

	switch flags.output {
	case outputJSON:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(cat); err != nil {
			return &exitCodeError{code: orchestrator.ExitExecution, err: fmt.Errorf("encode catalog: %w", err)}
		}
		return nil
	case outputText, "":
		return writeCatalogText(stdout, &cat)
	default:
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("evidence catalog: invalid -o %q (want text|json)", flags.output)}
	}
}

func writeCatalogText(stdout io.Writer, cat *manualcatalog.Catalog) error {
	if _, err := fmt.Fprintf(stdout, "Manual Evidence Catalog: %s (v%s) — %d entries\n\n", cat.Framework, cat.Version, len(cat.Entries)); err != nil {
		return err
	}
	entries := make([]manualcatalog.Entry, len(cat.Entries))
	copy(entries, cat.Entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tCONTROL\tTYPE\tFREQUENCY\tNAME"); err != nil {
		return err
	}
	for i := range entries {
		e := &entries[i]
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.ID, e.Control, e.Type, e.Frequency, e.Name); err != nil {
			return err
		}
	}
	return tw.Flush()
}
