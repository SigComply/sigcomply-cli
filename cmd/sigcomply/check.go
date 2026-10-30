package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/builtin" // side-effect: registers every in-tree framework factory
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/builtin" // side-effect: registers every in-tree source factory
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
	_ "github.com/sigcomply/sigcomply-cli/internal/vault/builtin" // side-effect: registers every in-tree vault backend
	"github.com/sigcomply/sigcomply-cli/internal/vendorfanout"
)

type checkFlags struct {
	config             string
	verbose            bool
	cloudOn            bool
	cloudOff           bool
	cloudURL           string
	capturePayloadPath string
	cadence            string
	onPush             bool
	cadences           []string
	pr                 bool
	scheduled          bool
}

func newCheckCmd() *cobra.Command {
	var flags checkFlags
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Collect evidence, evaluate policies, and submit aggregated counts",
		Long: "`sigcomply check` runs the full pipeline:\n" +
			"  1. Plan policies for the selected framework and current period.\n" +
			"  2. Collect evidence from bound source plugins.\n" +
			"  3. Evaluate each policy's rule.\n" +
			"  4. Persist signed envelopes + per-policy results + run manifest to the vault.\n" +
			"  5. Optionally submit aggregated counts to the configured cloud endpoint.\n",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd.Context(), cmd.OutOrStdout(), &flags)
		},
	}
	cmd.Flags().StringVarP(&flags.config, "config", "c", ".sigcomply.yaml", "Path to project config")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Verbose logging")
	cmd.Flags().BoolVar(&flags.cloudOn, "cloud", false, "Force cloud submission (requires OIDC)")
	cmd.Flags().BoolVar(&flags.cloudOff, "no-cloud", false, "Disable cloud submission")
	cmd.Flags().StringVar(&flags.cloudURL, "cloud-url", "", "Cloud base URL override (defaults to .sigcomply.yaml cloud.base_url)")
	cmd.Flags().StringVar(&flags.capturePayloadPath, "capture-cloud-payload", "", "Write the cloud SubmissionPayload to this file instead of POSTing it (auditor escape hatch)")
	cmd.Flags().StringVar(&flags.cadence, "cadence", "", "Only evaluate policies whose effective cadence matches (continuous|hourly|daily|weekly|monthly|quarterly|annual)")
	cmd.Flags().BoolVar(&flags.onPush, "on-push", false, "Only evaluate policies whose on_push attribute is true")
	cmd.Flags().StringSliceVar(&flags.cadences, "cadences", nil, "Comma-separated cadence set (intersect: a policy matches if any of its effective cadences is in this set; 'on_push' is the virtual cadence value for the on_push axis)")
	cmd.Flags().BoolVar(&flags.pr, "pr", false, "PR-mode run: filter to on_push policies and retry a failing slot up to 5 times, waiting about 3 min in total")
	cmd.Flags().BoolVar(&flags.scheduled, "scheduled", false, "Scheduled-mode run: consult the per-framework execution-state, run whichever cadences are due, advance the state on success")
	cmd.MarkFlagsMutuallyExclusive("cadence", "on-push", "cadences", "pr", "scheduled")
	return cmd
}

func runCheck(ctx context.Context, stdout io.Writer, flags *checkFlags) error {
	cfg, registries, err := orchestrator.Bootstrap(flags.config)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}
	logger := log.New(os.Stderr, flags.verbose)

	fw, ok := frameworks.Lookup(cfg.Framework)
	if !ok {
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("framework %q not supported (registered: %v)", cfg.Framework, frameworks.IDs())}
	}
	if err := fw.Register(registries); err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("register %s: %w", cfg.Framework, err)}
	}
	// Expand fan-out catalog entries against the project's third-party
	// register before any source is wired: the manual.pdf plugin reads
	// this map to resolve folders, so the instances must be present
	// before collection, not after.
	vendorReg, err := spec.LoadVendorRegister(cfg)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}
	manualCatalog := vendorfanout.Apply(fw.ManualCatalog(), vendorReg)

	// Before any source is built, not after: a mistyped key is often the
	// reason the credential resolution that follows fails, and reporting
	// it afterwards would mean the operator never sees it — the eager
	// credential check stops the run first.
	emitConfigWarnings(logger, cfg)

	// Before any source is built: SigComply Cloud refuses a run without
	// the project ID, so finding out after a full collection wastes the
	// run, and the eager credential check would hide this error.
	cloudBase, err := resolveCloudBase(cfg, flags)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}
	if err := missingProjectIDError(cfg, flags, cloudBase); err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}

	if err := registerProductionSources(ctx, registries, cfg, manualCatalog); err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}

	// Tell the operator, before any API call, that `check` is about to
	// reach real infrastructure using ambient credentials — this is not a
	// dry run. The banner names sources and region/backend only; it never
	// prints a credential.
	printCollectionBanner(stdout, cfg)

	if err := evidencetypes.VerifyRegistrations(registries); err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}

	v, err := vault.FromConfig(ctx, &cfg.Vault)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("vault: %w", err)}
	}

	commitSHA, commitTime := gitContext(ctx, logger)
	mode := orchestrator.ModeManual
	switch {
	case flags.pr:
		mode = orchestrator.ModePR
	case flags.scheduled:
		mode = orchestrator.ModeScheduled
	}
	res, err := orchestrator.Run(ctx, &orchestrator.Options{
		Config:             cfg,
		Registries:         registries,
		Vault:              v,
		CLIVersion:         cliVersion,
		CommitSHA:          commitSHA,
		CommitTime:         commitTime,
		Branch:             detectBranch(),
		Stdout:             stdout,
		Logger:             logger,
		CapturePayloadPath: flags.capturePayloadPath,
		Mode:               mode,
		Filter: planner.Filter{
			Cadence:  flags.cadence,
			OnPush:   flags.onPush,
			Cadences: flags.cadences,
		},
		SubmitterOpts: submitter.Options{
			BaseURL:    cloudBase,
			Force:      flags.cloudOn,
			Disable:    flags.cloudOff,
			CLIVersion: cliVersion,
			ProjectID:  cfg.Cloud.ProjectID,
		},
	})
	if err != nil {
		// Run classifies its own failures (config/plan errors are
		// ExitConfig); only fall back to ExitExecution when it didn't.
		code := res.ExitCode
		if code == orchestrator.ExitOK {
			code = orchestrator.ExitExecution
		}
		return &exitCodeError{code: code, err: err}
	}
	printRunLocation(stdout, &cfg.Vault, res.RunRoot)
	if res.ExitCode != orchestrator.ExitOK {
		return &exitCodeError{code: res.ExitCode}
	}
	return nil
}

// emitConfigWarnings logs every non-fatal config finding: keys no
// source, vault backend or experimental feature reads, local storage in
// a CI job, and an AWS web identity token minted for SigComply Cloud.
func emitConfigWarnings(logger *log.Logger, cfg *spec.ProjectConfig) {
	for _, w := range planner.SourceConfigWarnings(cfg) {
		logger.Warnf("source-config: %s", w)
	}
	for _, w := range planner.ExperimentalKeyWarnings(cfg) {
		logger.Warnf("config: %s", w)
	}
	for _, w := range vault.ConfigWarnings(&cfg.Vault) {
		logger.Warnf("config: %s", w)
	}
	for _, w := range ciLocalStorageWarnings(cfg, submitter.InCI()) {
		logger.Warnf("config: %s", w)
	}
	if w := submitter.AWSWebIdentityAudienceWarning(); w != "" {
		logger.Warnf("oidc: %s", w)
	}
}

// resolveCloudBase picks the cloud URL (--cloud-url over cloud.base_url)
// and checks it up front, so a plain-http URL is a config error before
// the run rather than a warning after it.
func resolveCloudBase(cfg *spec.ProjectConfig, flags *checkFlags) (string, error) {
	cloudBase := cfg.Cloud.BaseURL
	if flags.cloudURL != "" {
		cloudBase = flags.cloudURL
	}
	if cloudBase != "" && !flags.cloudOff {
		if err := submitter.ValidateBaseURL(cloudBase); err != nil {
			return "", err
		}
	}
	return cloudBase, nil
}

// missingProjectIDError returns the config error for a run that would
// submit without cloud.project_id, or nil. A run would submit when a
// cloud URL is resolved (cloud.base_url or --cloud-url), --no-cloud is
// not set, it writes no captured payload instead of POSTing, and it
// covers every policy (unfiltered or --scheduled); a filtered run never
// submits (orchestrator.handleSubmission), so it is unaffected. --cloud
// only forces a submission that would otherwise be skipped, so it needs
// the ID too. It applies outside CI as well, so the operator hears about
// it before CI does. Only the committed file may set the ID, never a
// flag or an env var: the commit is what shows the repository chose the
// project.
func missingProjectIDError(cfg *spec.ProjectConfig, flags *checkFlags, cloudBase string) error {
	if cloudBase == "" || flags.cloudOff || cfg.Cloud.ProjectID != "" || flags.capturePayloadPath != "" || filteredRun(flags) {
		return nil
	}
	return errors.New("cloud.project_id is not set in .sigcomply.yaml, and SigComply Cloud refuses runs without it: " +
		"copy the Project ID from your project's page on the SigComply dashboard into cloud.project_id, " +
		"or pass --no-cloud to run without submitting")
}

// filteredRun reports whether the flags select a subset of policies.
// It mirrors the orchestrator: --pr always narrows to on-push policies,
// and the cadence filters make planner.Filter.IsExplicit true.
func filteredRun(flags *checkFlags) bool {
	f := planner.Filter{Cadence: flags.cadence, OnPush: flags.onPush, Cadences: flags.cadences}
	return flags.pr || f.IsExplicit()
}

// ciLocalStorageWarnings flags local storage in a CI job. A local vault
// lives on the runner and disappears with it, so the run's signed
// evidence is gone when the job ends; a local manual.pdf folder sees only
// files committed to the repository.
func ciLocalStorageWarnings(cfg *spec.ProjectConfig, inCI bool) []string {
	if !inCI {
		return nil
	}
	var out []string
	if cfg.Vault.Backend == backendLocal {
		out = append(out, fmt.Sprintf("the vault is the local folder %s; in CI it is deleted when the job ends. "+
			"Set vault.backend to s3, gcs or azure_blob to keep the evidence", cfg.Vault.Str("path")))
	}
	if raw, ok := cfg.Sources[manual.SourceID]; ok {
		if b := sources.StringOpt(raw, "backend"); b == "" || b == backendLocal {
			out = append(out, "sources.manual.pdf reads a local folder; in CI it sees only files committed to the repository. "+
				"Set its backend to s3, gcs or azure_blob to read uploaded documents")
		}
	}
	return out
}

// printRunLocation ends a run's output with where its results went and
// how to read them back. Without it nothing in the output names the vault
// or the run folder, and a mistyped vault block was invisible.
func printRunLocation(stdout io.Writer, vc *spec.VaultConfig, runRoot string) {
	if runRoot == "" {
		return
	}
	parts := strings.SplitN(runRoot, "/", 3)
	if len(parts) < 3 {
		return
	}
	_, _ = fmt.Fprintf(stdout, "\nResults written to %s/%s\n", vaultLocation(vc), runRoot)                                       //nolint:errcheck // status output
	_, _ = fmt.Fprintf(stdout, "Next: sigcomply report --period %s (add --view integrity to verify the signatures)\n", parts[1]) //nolint:errcheck // status output
}

// vaultLocation renders the vault as the URI form `report --vault`
// accepts, so the printed location can be pasted back.
func vaultLocation(vc *spec.VaultConfig) string {
	join := func(scheme, base string) string {
		if p := strings.Trim(vc.Str("prefix"), "/"); p != "" {
			return scheme + base + "/" + p
		}
		return scheme + base
	}
	switch vc.Backend {
	case backendLocal:
		return strings.TrimSuffix(vc.Str("path"), "/")
	case "s3":
		return join("s3://", vc.Str("bucket"))
	case "gcs":
		return join("gs://", vc.Str("bucket"))
	case "azure_blob":
		return join("az://", vc.Str("account")+"/"+vc.Str("container"))
	default:
		return vc.Backend + " vault"
	}
}

// registerProductionSources iterates cfg.Sources and dispatches each
// entry through the process-global sources.RegisterFactory registry
// (populated by package init() of every in-tree plugin and any
// project-local plugin compiled in via `sigcomply build`). The check
// command has no per-source knowledge — adding a new source is a
// matter of dropping a package under internal/sources/<id>/ (or
// .sigcomply/plugins/<id>/) with an init() that calls
// sources.RegisterFactory.
//
// See docs/architecture/04-source-plugins.md §The factory contract.
func registerProductionSources(ctx context.Context, registries *registry.Set, cfg *spec.ProjectConfig, catalog map[string]manual.CatalogEntry) error {
	extras := map[string]any{
		manual.FrameworkCatalogKey: catalog,
	}
	// Sorted so that a config with several broken sources always reports
	// the same one first; map order would make the error depend on the
	// run.
	ids := make([]string, 0, len(cfg.Sources))
	for id := range cfg.Sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		env := sources.Env{
			Config:          withRegionDefault(cfg.Sources[id], cfg.Vault.Str("region")),
			FrameworkExtras: extras,
		}
		plugin, err := sources.Build(ctx, id, env)
		if err != nil {
			return fmt.Errorf("source %q: %w", id, err)
		}
		// Registered under the configured key, which for an instance is
		// the bracketed form. sources.Build has already re-identified the
		// plugin to match, so the registry key and plugin.ID() agree.
		if err := registries.Sources.Register(plugin); err != nil {
			return fmt.Errorf("register source %q: %w", id, err)
		}
	}
	return nil
}

// printCollectionBanner writes a short notice naming the configured
// sources `check` will collect from, so a tester sees that the run
// authenticated against real infrastructure rather than a dry run. It
// prints region (API sources) or backend (manual.pdf) only — never a
// credential, key, or token.
func printCollectionBanner(stdout io.Writer, cfg *spec.ProjectConfig) {
	if len(cfg.Sources) == 0 {
		return
	}
	ids := make([]string, 0, len(cfg.Sources))
	for id := range cfg.Sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	vaultRegion := cfg.Vault.Str("region")
	_, _ = fmt.Fprintf(stdout, "Collecting evidence from %d configured source(s):\n", len(ids)) //nolint:errcheck // status output
	for _, id := range ids {
		_, _ = fmt.Fprintf(stdout, "  - %s%s\n", id, sourceBannerDetail(id, cfg.Sources[id], vaultRegion)) //nolint:errcheck // status output
	}
	_, _ = fmt.Fprintln(stdout, "SigComply issues read-only calls; raw evidence stays in your vault.") //nolint:errcheck // status output
}

// sourceBannerDetail returns the parenthetical shown after a source ID
// in the collection banner: region for API sources, backend for the
// manual.pdf singleton, empty when neither is known.
func sourceBannerDetail(id string, raw map[string]any, vaultRegion string) string {
	if id == manual.SourceID {
		backend := sources.StringOpt(raw, "backend")
		if backend == "" {
			backend = backendLocal
		}
		return fmt.Sprintf(" (manual evidence, backend %s)", backend)
	}
	// An instance that assumes a role reaches a different account, which
	// is the one thing about a multi-account run an operator must be able
	// to confirm at a glance. The ARN names an account, not a secret.
	if roleARN := sources.StringOpt(raw, "role_arn"); roleARN != "" {
		region := sources.StringOpt(raw, "region")
		if region == "" {
			region = vaultRegion
		}
		if region == "" {
			return fmt.Sprintf(" (assuming %s)", roleARN)
		}
		return fmt.Sprintf(" (region %s, assuming %s)", region, roleARN)
	}
	region := sources.StringOpt(raw, "region")
	if region == "" {
		region = vaultRegion
	}
	if region != "" {
		return fmt.Sprintf(" (region %s)", region)
	}
	return ""
}

// withRegionDefault preserves the legacy convenience that AWS source
// plugins fall back to the vault's region when their own config omits
// it. Other sources ignore the region key.
func withRegionDefault(raw map[string]any, vaultRegion string) map[string]any {
	if vaultRegion == "" {
		return raw
	}
	if _, hasRegion := raw["region"]; hasRegion {
		return raw
	}
	out := make(map[string]any, len(raw)+1)
	for k, v := range raw {
		out[k] = v
	}
	out["region"] = vaultRegion
	return out
}

func detectBranch() string {
	for _, env := range []string{"GITHUB_REF_NAME", "CI_COMMIT_REF_NAME", "GIT_BRANCH"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return ""
}

// gitContext returns the head commit SHA and time, falling back to
// environment variables (CI provides them) before invoking git. A
// missing git context is non-fatal — the run proceeds with zeroed
// values.
func gitContext(ctx context.Context, logger *log.Logger) (string, time.Time) {
	sha := os.Getenv("GITHUB_SHA")
	if sha == "" {
		sha = os.Getenv("CI_COMMIT_SHA")
	}
	if sha == "" {
		out, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
		if err == nil {
			sha = strings.TrimSpace(string(out))
		}
	}
	timeStr := os.Getenv("GITHUB_EVENT_HEAD_COMMIT_TIMESTAMP")
	if timeStr == "" {
		out, err := exec.CommandContext(ctx, "git", "show", "-s", "--format=%cI", "HEAD").Output()
		if err == nil {
			timeStr = strings.TrimSpace(string(out))
		}
	}
	commitTime := time.Now().UTC()
	if timeStr != "" {
		if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
			commitTime = t
		} else {
			logger.Debugf("git: parse commit time: %s", err.Error())
		}
	}
	return sha, commitTime
}
