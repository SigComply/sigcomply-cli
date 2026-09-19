package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/builtin" // side-effect: registers every in-tree framework factory
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/report"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
	_ "github.com/sigcomply/sigcomply-cli/internal/vault/builtin" // side-effect: registers every in-tree vault backend
)

// reportFlags carries every flag accepted by `sigcomply report`.
// Defaults come from the project config; explicit flags override them.
type reportFlags struct {
	config    string
	vaultURI  string
	framework string
	period    string
	view      string
	format    string
	out       string
}

func newReportCmd() *cobra.Command {
	var flags reportFlags
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Read-only auditor snapshot of the vault",
		Long: "`sigcomply report` produces snapshot views of the vault: latest-state,\n" +
			"exceptions register, run-by-run integrity verification, run scope,\n" +
			"control coverage, and the Statement of Applicability. Read-only — never\n" +
			"writes to the vault, never calls the cloud, never requires OIDC.\n\n" +
			"`--view coverage` answers what a compliance score cannot: for each control,\n" +
			"is it verified by inspecting your infrastructure, or satisfied merely by a\n" +
			"document being on file?\n\n" +
			"`--view soa` generates the Statement of Applicability that ISO/IEC\n" +
			"27001:2022 6.1.3 d requires and a Stage 1 auditor asks for first: per\n" +
			"catalog control, whether it applies, why, and whether it is implemented.\n" +
			"`--format csv` gives the spreadsheet auditors expect.\n\n" +
			"Time-series analytics (drift, deviation timelines, continuous-monitoring\n" +
			"alerts) are paid SigComply Cloud features and intentionally absent here.\n",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd.Context(), cmd.OutOrStdout(), &flags)
		},
	}
	cmd.Flags().StringVarP(&flags.config, "config", "c", ".sigcomply.yaml", "Path to project config")
	cmd.Flags().StringVar(&flags.vaultURI, "vault", "", "Vault URI (overrides project config). Supports paths and s3://, gs://, az:// URIs.")
	cmd.Flags().StringVarP(&flags.framework, "framework", "f", "", "Framework to report on (defaults to project config's framework)")
	cmd.Flags().StringVar(&flags.period, "period", "", "Period ID (e.g. 2026-Q1). Required.")
	cmd.Flags().StringVar(&flags.view, "view", "latest", "View: latest | exceptions | integrity | scope | coverage | soa")
	cmd.Flags().StringVar(&flags.format, "format", "text", "Output format: text | json | csv | pdf (pdf deferred to v1.x)")
	cmd.Flags().StringVar(&flags.out, "out", "", "Output file (required for non-text formats; default stdout for text)")
	return cmd
}

// runReport is the package-internal entry called by the Cobra command's
// RunE. Takes flags by pointer to avoid copying the bundle across
// helpers; the Cobra closure captures the address of the local flags
// struct, so a pointer is naturally available.
func runReport(ctx context.Context, stdout io.Writer, flags *reportFlags) error {
	if flags.period == "" {
		return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("report: --period is required (e.g. --period 2026-Q1)")}
	}
	if flags.format == "pdf" {
		// Documented carve-out: PDF rendering is deferred to v1.x. The
		// flag is accepted by the parser so the help text shows it, but
		// passing it surfaces a clear actionable error rather than a
		// silently truncated stub.
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("report: PDF format deferred to v1.x; use --format text or --format json (or --format csv)")}
	}

	cfg, err := loadReportConfig(flags)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}

	v, err := vault.FromConfig(ctx, &cfg.Vault)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("vault: %w", err)}
	}

	framework := flags.framework
	if framework == "" {
		framework = cfg.Framework
	}
	if framework == "" {
		return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("report: framework not set (use --framework or set in %s)", flags.config)}
	}

	view, err := parseView(flags.view)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}

	// The coverage and soa views must name controls that produced no
	// result at all, so they need the framework's catalog rather than
	// only what the vault happens to contain. Resolving it here keeps
	// internal/report free of a frameworks import. Registration is pure
	// in-process — no config, no network — so `report` still works with
	// just --vault and --framework.
	var controls []core.Control
	var policies []core.Policy
	if view == report.ViewCoverage || view == report.ViewSoA {
		controls, policies, err = frameworkCatalog(framework)
		if err != nil {
			return &exitCodeError{code: orchestrator.ExitConfig, err: err}
		}
	}

	// The applicability decisions are authored in the project config,
	// not observed in the vault — the one half of a Statement of
	// Applicability that has nowhere else to come from.
	//
	// The config is otherwise optional here: an auditor holding only a
	// vault path can read every other view without the customer's
	// .sigcomply.yaml. The SoA is the exception, because without it the
	// report would show every control as applicable and silently turn a
	// deliberate exclusion into an inclusion — on the one deliverable a
	// certification auditor reads first. Refusing is the honest answer;
	// a footnote nobody reads in a CSV is not.
	var controlConfigs map[string]spec.ControlConfig
	if view == report.ViewSoA {
		if !configLoaded(flags) {
			return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf(
				"report: --view soa needs the project config for its applicability decisions — "+
					"pass -c <path to .sigcomply.yaml>, or drop --vault/--framework so %s is read",
				flags.config)}
		}
		controlConfigs = cfg.Controls
	}

	snap, err := report.Build(ctx, &report.Input{
		Vault:          v,
		Framework:      framework,
		PeriodID:       flags.period,
		View:           view,
		Controls:       controls,
		Policies:       policies,
		ControlConfigs: controlConfigs,
	})
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitExecution, err: err}
	}

	return writeReport(stdout, flags, snap)
}

// configLoaded reports whether loadReportConfig actually read the
// project file, rather than synthesizing an empty config from the
// command line. Kept next to loadReportConfig so the two conditions
// cannot drift apart.
func configLoaded(flags *reportFlags) bool {
	return flags.vaultURI == "" || flags.framework == ""
}

// loadReportConfig reads the project config and, when --vault is
// provided on the command line, overrides the parsed Vault block. The
// override path supports both absolute file paths and scheme-prefixed
// URIs (s3://, gs://, az://).
func loadReportConfig(flags *reportFlags) (*spec.ProjectConfig, error) {
	// The config file is optional when --vault and --framework are both
	// provided; auditors with just a vault path don't need the customer's
	// .sigcomply.yaml to read snapshots.
	var cfg spec.ProjectConfig
	if flags.vaultURI == "" || flags.framework == "" {
		data, err := os.ReadFile(flags.config)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		parsed, err := spec.LoadProjectConfig(data)
		if err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		cfg = parsed
	}
	if flags.vaultURI != "" {
		vaultCfg, err := vaultConfigFromURI(flags.vaultURI)
		if err != nil {
			return nil, err
		}
		cfg.Vault = vaultCfg
	}
	if flags.framework != "" {
		cfg.Framework = flags.framework
	}
	return &cfg, nil
}

// vaultConfigFromURI maps a CLI-supplied --vault value onto a
// spec.VaultConfig the factory can consume. Supports:
//
//	local path:      /var/sigcomply/vault         (or ./relative/path)
//	file scheme:     file:///var/sigcomply/vault
//	S3 / GCS / Azure: s3://bucket[/prefix], gs://bucket[/prefix],
//	                  az://account/container[/prefix]
//
// The mapping is intentionally narrow — anything more elaborate
// (force_path_style, custom endpoint, role_arn) belongs in the project
// config file, not in a CLI flag.
func vaultConfigFromURI(uri string) (spec.VaultConfig, error) {
	switch {
	case strings.HasPrefix(uri, "s3://"):
		bucket, prefix := splitBucketPrefix(strings.TrimPrefix(uri, "s3://"))
		return spec.VaultConfig{Backend: "s3", Config: map[string]any{"bucket": bucket, "prefix": prefix}}, nil
	case strings.HasPrefix(uri, "gs://"):
		bucket, prefix := splitBucketPrefix(strings.TrimPrefix(uri, "gs://"))
		return spec.VaultConfig{Backend: "gcs", Config: map[string]any{"bucket": bucket, "prefix": prefix}}, nil
	case strings.HasPrefix(uri, "az://"):
		rest := strings.TrimPrefix(uri, "az://")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 2 {
			return spec.VaultConfig{}, fmt.Errorf("--vault: az:// URI must be az://<account>/<container>[/prefix]")
		}
		var prefix string
		if len(parts) == 3 {
			prefix = parts[2]
		}
		return spec.VaultConfig{Backend: "azure_blob", Config: map[string]any{"account": parts[0], "container": parts[1], "prefix": prefix}}, nil
	case strings.HasPrefix(uri, "file://"):
		return spec.VaultConfig{Backend: "local", Config: map[string]any{"path": strings.TrimPrefix(uri, "file://")}}, nil
	default:
		return spec.VaultConfig{Backend: "local", Config: map[string]any{"path": uri}}, nil
	}
}

// splitBucketPrefix splits "bucket/prefix/with/slashes" into
// ("bucket", "prefix/with/slashes"). A bare "bucket" yields ("bucket",
// "").
func splitBucketPrefix(raw string) (bucket, prefix string) {
	slash := strings.Index(raw, "/")
	if slash < 0 {
		return raw, ""
	}
	return raw[:slash], raw[slash+1:]
}

func parseView(s string) (report.View, error) {
	switch report.View(s) {
	case report.ViewLatest, report.ViewExceptions, report.ViewIntegrity, report.ViewScope,
		report.ViewCoverage, report.ViewSoA:
		return report.View(s), nil
	case "":
		return report.ViewLatest, nil
	default:
		return "", fmt.Errorf("report: invalid --view %q (want latest|exceptions|integrity|scope|coverage|soa)", s)
	}
}

// frameworkCatalog resolves a framework's declared controls and the
// policies mapped to them, straight from the compiled registries.
func frameworkCatalog(id string) ([]core.Control, []core.Policy, error) {
	factory, ok := frameworks.Lookup(id)
	if !ok {
		return nil, nil, fmt.Errorf("report: framework %q not supported (registered: %v)", id, frameworks.IDs())
	}
	set := registry.NewSet()
	if err := factory.Register(set); err != nil {
		return nil, nil, fmt.Errorf("report: register %s: %w", id, err)
	}
	fw, ok := set.Frameworks.Lookup(id)
	if !ok {
		return nil, nil, fmt.Errorf("report: framework %q did not register itself", id)
	}
	policies := make([]core.Policy, 0, len(fw.Policies()))
	for _, ref := range fw.Policies() {
		p, ok := set.Policies.Lookup(ref.PolicyID)
		if !ok {
			continue
		}
		policies = append(policies, p)
	}
	return fw.Controls(), policies, nil
}

// writeReport routes the snapshot through the requested formatter
// to the requested sink (stdout for text by default, --out file
// otherwise). Non-text formats require --out so the bytes don't end up
// interleaved with shell prompts; this keeps automation predictable.
func writeReport(stdout io.Writer, flags *reportFlags, snap *report.Snapshot) error {
	if flags.format != "text" && flags.out == "" {
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("report: --out is required for --format %s (only text defaults to stdout)", flags.format)}
	}
	if flags.out == "" {
		return formatTo(stdout, flags.format, snap)
	}
	f, err := os.OpenFile(flags.out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitExecution, err: fmt.Errorf("open out file: %w", err)}
	}
	formatErr := formatTo(f, flags.format, snap)
	closeErr := f.Close()
	if formatErr != nil {
		return formatErr
	}
	if closeErr != nil {
		return &exitCodeError{code: orchestrator.ExitExecution, err: fmt.Errorf("close out file: %w", closeErr)}
	}
	return nil
}

func formatTo(sink io.Writer, format string, snap *report.Snapshot) error {
	switch format {
	case "text":
		return report.FormatText(sink, snap)
	case "json":
		return report.FormatJSON(sink, snap)
	case "csv":
		return report.FormatCSV(sink, snap)
	default:
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("report: invalid --format %q (want text|json|csv|pdf)", format)}
	}
}
