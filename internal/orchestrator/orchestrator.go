// Package orchestrator is L9 of the SigComply CLI: wires L3 through
// L8 for the `sigcomply check` command — config load, registry init,
// plan, collect, evaluate, persist, aggregate, submit, render. The
// only layer that talks to the human, owns the exit codes, and
// performs CI environment detection.
//
// See docs/architecture/02-layers.md §L9.
package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sigcomply/sigcomply-cli/internal/aggregator"
	"github.com/sigcomply/sigcomply-cli/internal/collector"
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
)

// Exit codes match docs/architecture/02-layers.md §Layered errors.
const (
	ExitOK        = 0
	ExitViolation = 1
	ExitExecution = 2
	ExitConfig    = 3
)

// ManifestSchemaVersion is the run-manifest schema stamped at write time.
const ManifestSchemaVersion = "run.v1"

// Options is the input to Run. Most fields come from CLI flags or the
// project config. Registries and Vault are pre-constructed by Bootstrap
// so tests can inject in-memory backends without redoing config load.
type Options struct {
	Config     *spec.ProjectConfig
	Registries *registry.Set
	Vault      core.Vault

	// CLI metadata, stamped on outputs.
	CLIVersion string
	CommitSHA  string
	CommitTime time.Time
	Branch     string

	// Output controls.
	Stdout io.Writer
	Logger *log.Logger

	// Submission overrides.
	ForceCloud   bool
	DisableCloud bool

	// CapturePayloadPath, when non-empty, writes the SubmissionPayload
	// JSON to disk instead of POSTing it. Powers the auditor-facing
	// --capture-cloud-payload escape hatch.
	CapturePayloadPath string

	// Now is the run's reference time. Tests inject deterministic values;
	// production callers leave nil.
	Now func() time.Time

	// Submitter overrides for tests.
	SubmitterOpts submitter.Options
}

// Result is what Run returns to the CLI command. ExitCode is the
// recommended exit code; the caller may override (e.g. when policy
// fail_on_violation is disabled).
type Result struct {
	ExitCode    int
	RunID       string
	RunRoot     string
	Summary     core.RunSummary
	Submitted   bool
	SubmittedAt time.Time
}

// Run executes the full sigcomply check pipeline.
func Run(ctx context.Context, opts *Options) (Result, error) {
	if opts == nil {
		return Result{ExitCode: ExitConfig}, fmt.Errorf("orchestrator: nil Options")
	}
	if err := validateOptions(opts); err != nil {
		return Result{ExitCode: ExitConfig}, err
	}
	startedAt := nowOrFallback(opts.Now)
	runID := uuid.NewString()

	plan, err := planner.Plan(&planner.Input{
		Config:     opts.Config,
		Registries: opts.Registries,
		CommitTime: opts.CommitTime,
		Now:        startedAt,
	})
	if err != nil {
		return Result{ExitCode: ExitConfig}, fmt.Errorf("plan: %w", err)
	}
	runRoot := buildRunRoot(plan.Framework, plan.Period.ID, startedAt, runID)
	rec := newRecordingVault(opts.Vault)

	collectOut, err := runCollect(ctx, opts, plan, rec, runRoot, startedAt)
	if err != nil {
		return Result{ExitCode: ExitExecution}, err
	}

	results, err := evaluator.Evaluate(ctx, &evaluator.Input{
		Plan:                  plan,
		Rules:                 opts.Registries.Rules,
		RecordsByPolicy:       collectOut.RecordsByPolicy,
		EnvelopesByPolicy:     collectOut.EnvelopesByPolicy,
		CollectErrorsByPolicy: collectOut.CollectErrorsByPolicy,
		Now:                   startedAt,
	})
	if err != nil {
		return Result{ExitCode: ExitExecution}, fmt.Errorf("evaluate: %w", err)
	}

	completedAt := nowOrFallback(opts.Now)
	persistResults(ctx, rec, opts.Logger, runRoot, results, runID, plan, completedAt)

	if err := writeManifest(ctx, rec, opts.Logger, runRoot, runID, plan, startedAt, completedAt); err != nil {
		return Result{ExitCode: ExitExecution}, err
	}

	payload := buildPayload(opts, results, plan, runID, startedAt, completedAt)
	submitted, submittedAt := handleSubmission(ctx, opts, &payload, completedAt)

	exitCode := renderAndExitCode(opts.Stdout, plan, results, opts.Config.CI)
	return Result{
		ExitCode:    exitCode,
		RunID:       runID,
		RunRoot:     runRoot,
		Summary:     payload.Summary,
		Submitted:   submitted,
		SubmittedAt: submittedAt,
	}, nil
}

func validateOptions(opts *Options) error {
	if opts.Config == nil {
		return fmt.Errorf("orchestrator: nil ProjectConfig")
	}
	if opts.Registries == nil {
		return fmt.Errorf("orchestrator: nil registries")
	}
	if opts.Vault == nil {
		return fmt.Errorf("orchestrator: nil vault")
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	return nil
}

func nowOrFallback(now func() time.Time) time.Time {
	if now != nil {
		return now()
	}
	return time.Now().UTC()
}

func runCollect(ctx context.Context, opts *Options, plan *planner.RunPlan, rec *recordingVault, runRoot string, now time.Time) (*collector.Output, error) {
	out, err := collector.Collect(ctx, &collector.Input{
		Plan:    plan,
		Sources: opts.Registries.Sources,
		Vault:   rec,
		RunRoot: runRoot,
		SlotParamsExtras: map[string]any{
			"period_id":    plan.Period.ID,
			"period_start": plan.Period.Start,
			"period_end":   plan.Period.End,
			"now":          now,
		},
		Now: now,
	})
	if err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}
	for pid, cerr := range out.CollectErrorsByPolicy {
		opts.Logger.Warnf("collector: policy %s: %s", pid, cerr.Error())
	}
	return out, nil
}

func persistResults(ctx context.Context, rec *recordingVault, logger *log.Logger, runRoot string, results []core.PolicyResult, runID string, plan *planner.RunPlan, completedAt time.Time) {
	for i := range results {
		r := &results[i]
		if err := rec.PutJSON(ctx, fmt.Sprintf("%s/policies/%s/result.json", runRoot, r.PolicyID), r); err != nil {
			logger.Warnf("vault: write result.json for %s: %s", r.PolicyID, err.Error())
		}
	}
	summary := summaryFromResults(results, runID, plan, completedAt)
	if err := rec.PutJSON(ctx, fmt.Sprintf("%s/summary.json", runRoot), summary); err != nil {
		logger.Warnf("vault: write summary.json: %s", err.Error())
	}
}

func writeManifest(ctx context.Context, rec *recordingVault, logger *log.Logger, runRoot, runID string, plan *planner.RunPlan, startedAt, completedAt time.Time) error {
	manifest := &core.Manifest{
		SchemaVersion:     ManifestSchemaVersion,
		RunID:             runID,
		Framework:         plan.Framework,
		PeriodID:          plan.Period.ID,
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
		FileHashes:        rec.FileHashes(runRoot),
		ExceptionsApplied: collectAppliedExceptions(plan),
	}
	if err := sign.Manifest(manifest); err != nil {
		return fmt.Errorf("sign manifest: %w", err)
	}
	// Don't include manifest.json in its own file_hashes — the signature
	// covers the table, and the table covers every other file.
	if err := rec.PutJSON(ctx, fmt.Sprintf("%s/manifest.json", runRoot), manifest); err != nil {
		logger.Warnf("vault: write manifest.json: %s", err.Error())
	}
	return nil
}

// collectAppliedExceptions snapshots the planner-resolved exceptions
// for the run. Ordered by policy_id so the manifest is deterministic
// across runs with identical inputs — auditors comparing two runs by
// hash should see no spurious diffs from map iteration order.
func collectAppliedExceptions(plan *planner.RunPlan) []core.AppliedException {
	out := make([]core.AppliedException, 0)
	for i := range plan.Policies {
		pp := &plan.Policies[i]
		if pp.Exception == nil {
			continue
		}
		out = append(out, core.AppliedException{
			PolicyID:        pp.Spec.ID,
			State:           string(pp.Exception.State),
			Reason:          pp.Exception.Reason,
			ApprovedBy:      pp.Exception.ApprovedBy,
			ApprovedAt:      pp.Exception.ApprovedAt,
			ExpiresAt:       pp.Exception.ExpiresAt,
			ResourceID:      pp.Exception.ResourceID,
			ResourcePattern: pp.Exception.ResourcePattern,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PolicyID < out[j].PolicyID })
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildPayload(opts *Options, results []core.PolicyResult, plan *planner.RunPlan, runID string, startedAt, completedAt time.Time) core.SubmissionPayload {
	env := aggregator.Environment{
		RunID:       runID,
		Framework:   plan.Framework,
		PeriodID:    plan.Period.ID,
		CommitSHA:   opts.CommitSHA,
		CommitTime:  opts.CommitTime,
		Branch:      opts.Branch,
		Repository:  detectRepository(),
		CI:          detectCIEnvironment(),
		CLIVersion:  opts.CLIVersion,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
	}
	return aggregator.Build(results, &env)
}

func handleSubmission(ctx context.Context, opts *Options, payload *core.SubmissionPayload, completedAt time.Time) (bool, time.Time) {
	if opts.CapturePayloadPath != "" {
		if err := writeCapturedPayload(opts.CapturePayloadPath, payload); err != nil {
			opts.Logger.Warnf("capture payload: %s", err.Error())
		}
		return false, time.Time{}
	}
	decision := submitter.Decide(opts.SubmitterOpts, submitter.HasOIDC(), submitter.InCI())
	switch decision {
	case submitter.DecisionSubmit:
		resp, err := submitter.Submit(ctx, opts.SubmitterOpts, payload)
		if err != nil {
			opts.Logger.Warnf("submit: %s", err.Error())
			return false, time.Time{}
		}
		opts.Logger.Infof("submission accepted (HTTP %d)", resp.StatusCode)
		return true, completedAt
	case submitter.DecisionMissingToken:
		opts.Logger.Warnf("submit: --cloud was set but no OIDC token detected; skipping")
	case submitter.DecisionSkip:
		// no-op
	}
	return false, time.Time{}
}

func buildRunRoot(framework, periodID string, now time.Time, runID string) string {
	stamp := now.UTC().Format("20060102T150405Z")
	short := runID
	if len(short) > 8 {
		short = short[:8]
	}
	return fmt.Sprintf("%s/%s/run_%s_%s", framework, periodID, stamp, short)
}

// recordingVault wraps a core.Vault and captures SHA-256 hashes of every
// byte stream written. Used to populate Manifest.FileHashes after the
// run completes. The wrapper itself satisfies core.Vault.
type recordingVault struct {
	inner  core.Vault
	hashes map[string]string
}

func newRecordingVault(inner core.Vault) *recordingVault {
	return &recordingVault{inner: inner, hashes: map[string]string{}}
}

func (v *recordingVault) Init(ctx context.Context) error { return v.inner.Init(ctx) }
func (v *recordingVault) PutEnvelope(ctx context.Context, path string, e *core.Envelope) error {
	body, err := sign.EncodeEnvelope(e)
	if err != nil {
		return err
	}
	v.record(path, body)
	return v.inner.PutEnvelope(ctx, path, e)
}
func (v *recordingVault) PutJSON(ctx context.Context, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	v.record(path, data)
	return v.inner.PutJSON(ctx, path, body)
}
func (v *recordingVault) PutBinary(ctx context.Context, path string, body []byte, meta map[string]string) error {
	v.record(path, body)
	return v.inner.PutBinary(ctx, path, body, meta)
}
func (v *recordingVault) GetBinary(ctx context.Context, path string) ([]byte, error) {
	return v.inner.GetBinary(ctx, path)
}
func (v *recordingVault) List(ctx context.Context, prefix string) ([]string, error) {
	return v.inner.List(ctx, prefix)
}
func (v *recordingVault) record(path string, data []byte) {
	h := sha256.Sum256(data)
	v.hashes[path] = "sha256:" + hex.EncodeToString(h[:])
}

// FileHashes returns the hash table keyed by paths relative to runRoot;
// the manifest itself is excluded so the manifest's signature is the
// trust root.
func (v *recordingVault) FileHashes(runRoot string) map[string]string {
	prefix := runRoot + "/"
	out := make(map[string]string, len(v.hashes))
	for path, hash := range v.hashes {
		rel := strings.TrimPrefix(path, prefix)
		if rel == "manifest.json" {
			continue
		}
		out[rel] = hash
	}
	return out
}

func summaryFromResults(results []core.PolicyResult, runID string, plan *planner.RunPlan, completedAt time.Time) map[string]any {
	out := map[string]any{
		"schema_version": "summary.v1",
		"run_id":         runID,
		"framework":      plan.Framework,
		"period_id":      plan.Period.ID,
		"completed_at":   completedAt,
		"policies":       results,
	}
	return out
}

func detectRepository() core.Repository {
	if g := os.Getenv("GITHUB_REPOSITORY"); g != "" {
		return core.Repository{Provider: "github", NameSlug: g, URL: "https://github.com/" + g}
	}
	if p := os.Getenv("CI_PROJECT_PATH"); p != "" {
		url := os.Getenv("CI_PROJECT_URL")
		return core.Repository{Provider: "gitlab", NameSlug: p, URL: url}
	}
	return core.Repository{Provider: "local"}
}

func detectCIEnvironment() core.CIEnvironment {
	if os.Getenv("GITHUB_ACTIONS") != "" {
		runID := os.Getenv("GITHUB_RUN_ID")
		repo := os.Getenv("GITHUB_REPOSITORY")
		var runURL string
		if runID != "" && repo != "" {
			runURL = fmt.Sprintf("https://github.com/%s/actions/runs/%s", repo, runID)
		}
		return core.CIEnvironment{Provider: "github", Workflow: os.Getenv("GITHUB_WORKFLOW"), RunURL: runURL}
	}
	if os.Getenv("GITLAB_CI") != "" {
		return core.CIEnvironment{Provider: "gitlab", Workflow: os.Getenv("CI_JOB_NAME"), RunURL: os.Getenv("CI_JOB_URL")}
	}
	return core.CIEnvironment{Provider: "local"}
}

func writeCapturedPayload(path string, payload *core.SubmissionPayload) error {
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

func renderAndExitCode(stdout io.Writer, plan *planner.RunPlan, results []core.PolicyResult, ci spec.CIConfig) int {
	var passed, failed, skipped, errored, na, waived int
	for i := range results {
		switch results[i].Status {
		case core.StatusPass:
			passed++
		case core.StatusFail:
			failed++
		case core.StatusSkip:
			skipped++
		case core.StatusError:
			errored++
		case core.StatusNA:
			na++
		case core.StatusWaived:
			waived++
		}
	}
	_, _ = fmt.Fprintf(stdout, "SigComply check %s/%s — %d policies\n", plan.Framework, plan.Period.ID, len(results))                //nolint:errcheck // status output
	_, _ = fmt.Fprintf(stdout, "  pass=%d fail=%d skip=%d error=%d na=%d waived=%d\n", passed, failed, skipped, errored, na, waived) //nolint:errcheck // status output
	sortedResults := make([]core.PolicyResult, len(results))
	copy(sortedResults, results)
	sort.Slice(sortedResults, func(i, j int) bool { return sortedResults[i].PolicyID < sortedResults[j].PolicyID })
	for i := range sortedResults {
		r := &sortedResults[i]
		_, _ = fmt.Fprintf(stdout, "  [%s] %s — %s\n", r.Status, r.PolicyID, r.ControlID) //nolint:errcheck // status output
	}
	if errored > 0 {
		return ExitExecution
	}
	if failed > 0 && shouldFail(ci) {
		return ExitViolation
	}
	return ExitOK
}

func shouldFail(ci spec.CIConfig) bool {
	// Default is fail-on-violation = true.
	if ci.FailOnViolation == nil {
		return true
	}
	return *ci.FailOnViolation
}

// Bootstrap is a convenience helper for tests and the CLI command:
// loads the config file and constructs an empty registry set ready
// for framework registration. The vault is constructed by the caller
// so tests can inject in-memory backends.
func Bootstrap(configPath string) (*spec.ProjectConfig, *registry.Set, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap: read config: %w", err)
	}
	cfg, err := spec.LoadProjectConfig(data)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap: parse config: %w", err)
	}
	return &cfg, registry.NewSet(), nil
}

// ErrBootstrapAlreadyInitialized is reserved for future use.
var ErrBootstrapAlreadyInitialized = errors.New("orchestrator: already initialized")
