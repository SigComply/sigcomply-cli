package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/manualdue"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/manual/builtin" // side-effect: registers the s3/gcs/azure_blob manual backends
)

// manualSourceID is the project-level singleton manual evidence source.
const manualSourceID = "manual.pdf"

// defaultWithinDays is the lead time used when --within-days is not
// given. Thirty days comfortably precedes the scaffolded cadence crons,
// which fire shortly before each period closes.
const defaultWithinDays = 30

type evidenceDueFlags struct {
	config     string
	withinDays int
	all        bool
}

func newEvidenceDueCmd(parent *evidenceFlags) *cobra.Command {
	var flags evidenceDueFlags
	cmd := &cobra.Command{
		Use:   "due",
		Short: "List manual evidence with no file for the current period",
		Long: "Reports every manual-evidence catalog entry whose folder for the current\n" +
			"period is empty, so the upload can happen before a scheduled run needs it.\n\n" +
			"An entry is reported only when its folder is genuinely empty — once the\n" +
			"file is uploaded the notice stops, so it never nags about work already\n" +
			"done. The command is read-only (LIST calls only; no file bytes are\n" +
			"downloaded, nothing is written, no cloud API is contacted) and it always\n" +
			"exits 0 when the scan succeeds, so it is safe as a non-failing CI step.\n",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEvidenceDue(cmd.Context(), cmd.OutOrStdout(), parent, &flags)
		},
	}
	cmd.Flags().StringVarP(&flags.config, "config", "c", ".sigcomply.yaml", "Path to project config")
	cmd.Flags().IntVar(&flags.withinDays, "within-days", defaultWithinDays,
		"Only report entries whose period ends within this many days; 0 reports only overdue entries, negative reports all (overdue entries always report)")
	cmd.Flags().BoolVar(&flags.all, "all", false, "Report every entry with an empty folder, ignoring --within-days")
	return cmd
}

func runEvidenceDue(ctx context.Context, stdout io.Writer, parent *evidenceFlags, flags *evidenceDueFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, _, err := orchestrator.Bootstrap(flags.config)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("evidence due: %w", err)}
	}
	if err := validateOutputFormat(parent.output); err != nil {
		return err
	}
	catalog, fwID, err := manualCatalogFor(parent.framework, cfg.Framework)
	if err != nil {
		return err
	}

	raw, configured := cfg.Sources[manualSourceID]
	if !configured {
		// Not an error: a project may legitimately run automated-only.
		notef(stdout, "manual evidence: no %s source configured in %s — nothing to check\n",
			manualSourceID, flags.config)
		return nil
	}

	// The period must be derived exactly as `check` derives it, from the
	// HEAD commit time rather than the wall clock — otherwise this would
	// report on a different folder than the one the next run reads.
	_, commitTime := gitContext(ctx, log.New(io.Discard, false))
	period, err := planner.DerivePeriod(&cfg.Period, commitTime)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("evidence due: %w", err)}
	}

	reader, scheme, bucket, prefix, err := manual.NewReaderFromConfig(
		withRegionDefault(raw, cfg.Vault.Str("region")))
	if err != nil {
		// Credentials or backend wiring are missing. Say so plainly and
		// exit 0: an unverifiable folder is an unknown, and turning
		// unknowns into deadlines is how a warning loses its meaning.
		notef(stdout, "manual evidence: could not open the evidence store, skipping the due check (%v)\n", err)
		return nil
	}

	in := manualdue.Input{
		Framework: fwID,
		Catalog:   catalog,
		Reader:    reader,
		Scheme:    scheme,
		Bucket:    bucket,
		Prefix:    prefix,
		Period:    period,
		Now:       time.Now().UTC(),
	}
	in.Unfiltered = flags.all || flags.withinDays < 0
	if flags.withinDays > 0 {
		in.Within = time.Duration(flags.withinDays) * 24 * time.Hour
	}

	rep, err := manualdue.Scan(ctx, &in)
	if err != nil {
		notef(stdout, "manual evidence: could not list the evidence store, skipping the due check (%v)\n", err)
		return nil
	}
	return renderDue(stdout, parent.output, rep)
}

// validateOutputFormat rejects unsupported -o values up front, so the
// scan is not performed only to be discarded.
func validateOutputFormat(output string) error {
	switch output {
	case outputJSON, outputText, "":
		return nil
	default:
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("evidence due: invalid -o %q (want text|json)", output)}
	}
}

// manualCatalogFor resolves the framework from the flag, then the
// project config, then the environment/default, and returns its runtime
// manual catalog.
func manualCatalogFor(flagFramework, configFramework string) (catalog map[string]manual.CatalogEntry, fwID string, err error) {
	fwID = flagFramework
	if fwID == "" {
		fwID = configFramework
	}
	if fwID == "" {
		fwID = resolveFramework("")
	}
	factory, ok := frameworks.Lookup(fwID)
	if !ok {
		return nil, fwID, &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("evidence due: framework %q not supported (registered: %v)", fwID, frameworks.IDs())}
	}
	if factory.ManualCatalog == nil {
		return nil, fwID, &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("evidence due: framework %q has no manual catalog", fwID)}
	}
	return factory.ManualCatalog(), fwID, nil
}

func renderDue(stdout io.Writer, output string, rep *manualdue.Report) error {
	if output == outputJSON {
		if err := manualdue.FormatJSON(stdout, rep); err != nil {
			return &exitCodeError{code: orchestrator.ExitExecution, err: fmt.Errorf("evidence due: %w", err)}
		}
		return nil
	}
	if err := manualdue.FormatText(stdout, rep); err != nil {
		return &exitCodeError{code: orchestrator.ExitExecution, err: fmt.Errorf("evidence due: %w", err)}
	}
	emitCIAnnotations(stdout, rep)
	return nil
}

// note writes advisory output. Like the rest of the CLI's status
// printing, a failed write is not worth failing the command over.
func notef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...) //nolint:errcheck // advisory status output
}

// emitCIAnnotations adds platform-native side channels on top of the
// plain-text block, never in place of it. GitLab has no workflow-command
// equivalent, so there it stays plain text.
func emitCIAnnotations(stdout io.Writer, rep *manualdue.Report) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		_ = manualdue.FormatGitHubAnnotations(stdout, rep) //nolint:errcheck // advisory status output
	}
	summaryPath := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryPath == "" {
		return
	}
	// The path comes from the Actions runner, which created the file and
	// expects steps to append to it. The command never derives this path
	// from project config or user input.
	f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G703: runner-provided summary path
	if err != nil {
		return // the summary is a nicety; never let it affect the run
	}
	defer func() { _ = f.Close() }()     //nolint:errcheck // append-only advisory file
	_ = manualdue.FormatMarkdown(f, rep) //nolint:errcheck // advisory status output
}
