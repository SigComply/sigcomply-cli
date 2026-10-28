package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
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
	config string
	// configSet records an explicit -c. With --vault and --framework
	// both given the config is otherwise skipped; an explicit -c is how
	// the SoA gets its applicability decisions in that case.
	configSet bool
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
			"is an automated check mapped to it, and did that check inspect anything in\n" +
			"the period — or is it satisfied merely by a document being on file?\n\n" +
			"`--view soa` generates the Statement of Applicability that ISO/IEC\n" +
			"27001:2022 6.1.3 d requires and a Stage 1 auditor asks for first: per\n" +
			"catalog control, whether it applies, why, and whether it is implemented.\n" +
			"`--format csv` gives the spreadsheet auditors expect.\n\n" +
			"Time-series analytics (drift, deviation timelines, continuous-monitoring\n" +
			"alerts) are paid SigComply Cloud features and intentionally absent here.\n",
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags.configSet = cmd.Flags().Changed("config")
			return runReport(cmd.Context(), cmd.OutOrStdout(), &flags)
		},
	}
	cmd.Flags().StringVarP(&flags.config, "config", "c", ".sigcomply.yaml", "Path to project config")
	cmd.Flags().StringVar(&flags.vaultURI, "vault", "", "Vault URI (overrides project config). Supports paths and file://, s3://bucket[/prefix][?region=r], gs://, az:// URIs. An s3:// URI without ?region= uses AWS_REGION, AWS_DEFAULT_REGION, then the project config's vault region.")
	cmd.Flags().StringVarP(&flags.framework, "framework", "f", "", "Framework to report on (defaults to project config's framework)")
	cmd.Flags().StringVar(&flags.period, "period", "", "Period ID (e.g. 2026-Q1, or soc2/2026-Q1 as check prints it). Required.")
	cmd.Flags().StringVar(&flags.view, "view", "latest", "View: latest | exceptions | integrity | scope | coverage | soa")
	cmd.Flags().StringVar(&flags.format, "format", "text", "Output format: text | json | csv")
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
	if flags.format == "" {
		flags.format = outputText
	}
	// Checked before anything is read or opened: an invalid format
	// found only at write time would already have truncated --out.
	if err := validateReportFormat(flags.format); err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}

	view, err := parseView(flags.view)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}
	cfg, framework, periodID, err := resolveReportTarget(flags)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}
	v, err := openReportVault(ctx, &cfg.Vault)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}

	in, err := viewInput(flags, cfg, framework, view)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}
	in.Vault, in.PeriodID = v, periodID
	snap, err := report.Build(ctx, in)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitExecution, err: err}
	}
	// The SoA is the exception: its applicability half comes from the
	// config, and with no runs every control reads "not evaluated", so
	// an empty period is visible in the document itself.
	if snap.RunCount == 0 && view != report.ViewSoA {
		return noRunsError(ctx, v, framework, periodID)
	}

	if err := writeReport(stdout, flags, snap); err != nil {
		return err
	}
	return integrityVerdict(snap)
}

// viewInput resolves what the chosen view needs beyond the vault. The
// coverage and soa views must name controls that produced no result at
// all, so they need the framework's catalog rather than only what the
// vault happens to contain. Resolving it here keeps internal/report free
// of a frameworks import. Registration is pure in-process — no config,
// no network — so `report` still works with just --vault and
// --framework.
func viewInput(flags *reportFlags, cfg *spec.ProjectConfig, framework string, view report.View) (*report.Input, error) {
	in := &report.Input{Framework: framework, View: view}
	var err error
	if view == report.ViewCoverage || view == report.ViewSoA {
		in.Controls, in.Policies, err = frameworkCatalog(framework)
		if err != nil {
			return nil, err
		}
	}
	if view == report.ViewSoA {
		in.ControlConfigs, in.ControlRisks, err = soaDecisions(flags, cfg)
		if err != nil {
			return nil, err
		}
	}
	return in, nil
}

// resolveReportTarget loads the config and settles which framework and
// period the report reads.
func resolveReportTarget(flags *reportFlags) (cfg *spec.ProjectConfig, framework, periodID string, err error) {
	cfg, err = loadReportConfig(flags)
	if err != nil {
		return nil, "", "", err
	}
	framework = flags.framework
	if framework == "" {
		framework = cfg.Framework
	}
	if framework == "" {
		return nil, "", "", fmt.Errorf("report: framework not set (use --framework or set in %s)", flags.config)
	}
	periodID, err = normalizeReportPeriod(flags.period, framework)
	if err != nil {
		return nil, "", "", err
	}
	return cfg, framework, periodID, nil
}

// openReportVault opens the vault read-only in intent. The local backend
// creates its root on open; report never writes, and a missing directory
// here is a mistyped path, not an empty vault, so it is refused rather
// than created and reported as "no runs".
func openReportVault(ctx context.Context, vc *spec.VaultConfig) (core.Vault, error) {
	if vc.Backend == backendLocal {
		if _, err := os.Stat(vc.Str("path")); err != nil {
			return nil, fmt.Errorf("report: vault path %q: %w", vc.Str("path"), err)
		}
	}
	v, err := vault.FromConfig(ctx, vc)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	return v, nil
}

// validateReportFormat accepts the formats formatTo can write.
func validateReportFormat(format string) error {
	switch format {
	case outputText, outputJSON, "csv":
		return nil
	case "pdf":
		// The flag value is listed in the help text, so passing it gets
		// an actionable error rather than a silently truncated stub.
		return errors.New("report: PDF output is not available yet; use --format text, json or csv")
	default:
		return fmt.Errorf("report: invalid --format %q (want text|json|csv)", format)
	}
}

// normalizeReportPeriod accepts the period both as the bare ID and in
// the "<framework>/<period>" form `check` prints on its first line, so
// the value a user copies from that line works. Any other slash is an
// error: a period ID is one vault path segment.
func normalizeReportPeriod(period, framework string) (string, error) {
	id := strings.TrimPrefix(period, framework+"/")
	if strings.Contains(id, "/") {
		return "", fmt.Errorf("report: --period %q: pass the period ID alone (e.g. 2026-Q1), or %s/<period> for framework %s", period, framework, framework)
	}
	return id, nil
}

// noRunsError refuses a period with no run folders. An empty table with
// exit 0 would let an integrity gate pass on a typo'd period or vault,
// so the command exits 3 and lists the periods the vault does hold.
func noRunsError(ctx context.Context, v core.Vault, framework, periodID string) error {
	msg := fmt.Sprintf("report: no runs for %s/%s in this vault", framework, periodID)
	periods, err := report.ListPeriods(ctx, v, framework)
	switch {
	case err != nil:
		msg += fmt.Sprintf(" (listing other periods failed: %v)", err)
	case len(periods) == 0:
		msg += fmt.Sprintf("; it holds no %s runs at all: check --vault and --framework", framework)
	default:
		msg += "; periods with runs: " + strings.Join(periods, ", ")
	}
	return &exitCodeError{code: orchestrator.ExitConfig, err: errors.New(msg)}
}

// integrityVerdict turns a failed integrity check into exit 1, the
// code `check` uses for a failed policy. The view is what an auditor
// scripts against a vault; a "fail" row that still exits 0 passes any
// pipeline that reads only the exit code. The table is written first,
// so the reader still sees which run and which file failed.
func integrityVerdict(snap *report.Snapshot) error {
	if snap.Integrity == nil {
		return nil
	}
	failed := 0
	for i := range snap.Integrity.Runs {
		if snap.Integrity.Runs[i].Status() != "pass" {
			failed++
		}
	}
	if failed == 0 {
		return nil
	}
	return &exitCodeError{code: orchestrator.ExitViolation, err: fmt.Errorf(
		"report: integrity verification failed for %d of %d run(s)", failed, len(snap.Integrity.Runs))}
}

// soaDecisions returns the applicability decisions and the risk
// register's control links that a Statement of Applicability needs.
//
// The applicability decisions are authored in the project config, not
// observed in the vault — the one half of a Statement of Applicability
// that has nowhere else to come from.
//
// The config is otherwise optional here: an auditor holding only a
// vault path can read every other view without the customer's
// .sigcomply.yaml. The SoA is the exception, because without it the
// report would show every control as applicable and silently turn a
// deliberate exclusion into an inclusion — on the one deliverable a
// certification auditor reads first. Refusing is the honest answer;
// a footnote nobody reads in a CSV is not.
func soaDecisions(flags *reportFlags, cfg *spec.ProjectConfig) (decisions map[string]spec.ControlConfig, controlRisks map[string][]string, err error) {
	if !configLoaded(flags) {
		return nil, nil, errors.New(
			"report: --view soa needs the project config file, because the applicability " +
				"decisions live there; with both --vault and --framework set it is read only " +
				"when you pass it with -c <path>")
	}
	// The risk register supplies the other half of 6.1.3 d): the
	// justification for including a control. A malformed block is a
	// config error here for the same reason it is during a check —
	// silently dropping it would print a Statement of Applicability
	// that claims no risk drove any control.
	risks, err := spec.LoadRiskRegister(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg.Controls, risks.ControlRisks(), nil
}

// configLoaded reports whether loadReportConfig actually read the
// project file, rather than synthesizing an empty config from the
// command line. loadReportConfig calls it too, so the two cannot drift
// apart.
func configLoaded(flags *reportFlags) bool {
	return flags.configSet || flags.vaultURI == "" || flags.framework == ""
}

// loadReportConfig reads the project config and, when --vault is
// provided on the command line, overrides the parsed Vault block. The
// override path supports both absolute file paths and scheme-prefixed
// URIs (s3://, gs://, az://).
func loadReportConfig(flags *reportFlags) (*spec.ProjectConfig, error) {
	// The config file is optional when --vault and --framework are both
	// provided and -c is not; auditors with just a vault path don't need
	// the customer's .sigcomply.yaml to read snapshots.
	var cfg spec.ProjectConfig
	if configLoaded(flags) {
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
		if vaultCfg.Backend == "s3" && vaultCfg.Str(regionConfigKey) == "" {
			region := s3RegionFallback(&cfg.Vault)
			if region == "" {
				return nil, fmt.Errorf("--vault %s: the S3 vault needs a region: add ?region=<region> to the URI or set AWS_REGION", flags.vaultURI)
			}
			vaultCfg.Config[regionConfigKey] = region
		}
		cfg.Vault = vaultCfg
	}
	if flags.framework != "" {
		cfg.Framework = flags.framework
	}
	return &cfg, nil
}

// prefixConfigKey is the spec.VaultConfig key holding the object-store
// key prefix for the bucket-backed vault backends; regionConfigKey holds
// the S3 backend's region.
const (
	prefixConfigKey = "prefix"
	regionConfigKey = "region"
)

// s3RegionFallback supplies the region an s3:// --vault URI left out:
// the usual AWS environment variables first, then the project config's
// vault region when that vault is S3 too. The S3 backend requires a
// region, and before this an s3:// URI had no way to give one.
func s3RegionFallback(projectVault *spec.VaultConfig) string {
	for _, env := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if r := os.Getenv(env); r != "" {
			return r
		}
	}
	if projectVault.Backend == "s3" {
		return projectVault.Str(regionConfigKey)
	}
	return ""
}

// vaultConfigFromURI maps a CLI-supplied --vault value onto a
// spec.VaultConfig the factory can consume. Supports:
//
//	local path:      /var/sigcomply/vault         (or ./relative/path)
//	file scheme:     file:///var/sigcomply/vault
//	S3 / GCS / Azure: s3://bucket[/prefix][?region=r], gs://bucket[/prefix],
//	                  az://account/container[/prefix]
//
// The mapping is intentionally narrow — anything more elaborate
// (force_path_style, custom endpoint, role_arn) belongs in the project
// config file, not in a CLI flag.
func vaultConfigFromURI(uri string) (spec.VaultConfig, error) {
	switch {
	case strings.HasPrefix(uri, "s3://"):
		rest, query, _ := strings.Cut(strings.TrimPrefix(uri, "s3://"), "?")
		bucket, prefix := splitBucketPrefix(rest)
		out := spec.VaultConfig{Backend: "s3", Config: map[string]any{"bucket": bucket, prefixConfigKey: prefix}}
		if query != "" {
			params, err := url.ParseQuery(query)
			if err != nil {
				return spec.VaultConfig{}, fmt.Errorf("--vault: %w", err)
			}
			for k := range params {
				if k != regionConfigKey {
					return spec.VaultConfig{}, fmt.Errorf("--vault: unsupported s3:// parameter %q (only ?region= is accepted; anything else belongs in the project config)", k)
				}
			}
			if r := params.Get(regionConfigKey); r != "" {
				out.Config[regionConfigKey] = r
			}
		}
		return out, nil
	case strings.HasPrefix(uri, "gs://"):
		bucket, prefix := splitBucketPrefix(strings.TrimPrefix(uri, "gs://"))
		return spec.VaultConfig{Backend: "gcs", Config: map[string]any{"bucket": bucket, prefixConfigKey: prefix}}, nil
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
		return spec.VaultConfig{Backend: "azure_blob", Config: map[string]any{"account": parts[0], "container": parts[1], prefixConfigKey: prefix}}, nil
	case strings.HasPrefix(uri, "file://"):
		return spec.VaultConfig{Backend: backendLocal, Config: map[string]any{"path": strings.TrimPrefix(uri, "file://")}}, nil
	default:
		return spec.VaultConfig{Backend: backendLocal, Config: map[string]any{"path": uri}}, nil
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
		return &exitCodeError{code: orchestrator.ExitConfig, err: validateReportFormat(format)}
	}
}
