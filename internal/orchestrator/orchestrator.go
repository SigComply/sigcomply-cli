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
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sigcomply/sigcomply-cli/internal/aggregator"
	"github.com/sigcomply/sigcomply-cli/internal/collector"
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
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

// Mode determines the higher-level run shape. ModeManual is the
// default (one-shot ad-hoc check); ModePR is for PR/push-triggered
// CI, narrows the plan to on_push policies and uses a generous slot
// retry budget; ModeScheduled is for cron-triggered CI, reads the
// per-policy state shards, decides which policies are due, and
// advances state on success. See
// docs/architecture/11-cadence-model.md §Modes.
type Mode string

// Mode values.
const (
	// ModeManual is the default ad-hoc one-shot run shape.
	ModeManual Mode = ""
	// ModePR narrows to on_push policies and uses a generous slot retry budget.
	ModePR Mode = "pr"
	// ModeScheduled consults per-policy state, gates evaluation by cadence,
	// and advances state on success.
	ModeScheduled Mode = "scheduled"
)

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

	// Filter narrows the plan to a subset of policies. The planner
	// enforces mutual exclusion across Filter's fields; the orchestrator
	// just threads it through. When Mode is ModePR and Filter's cadence
	// axes are unset, the orchestrator derives Filter.Cadences from the
	// mode (PR → [on_push]).
	Filter planner.Filter

	// Mode selects the higher-level run shape (manual / pr /
	// scheduled). See the Mode type for semantics. ModeManual is
	// the default and preserves legacy single-run behavior.
	Mode Mode
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

	filter, retryPolicy, runState := resolveMode(ctx, opts, startedAt)

	schemaDigests := computeSchemaDigests(opts.Registries)
	plan, err := planner.Plan(&planner.Input{
		Config:        opts.Config,
		Registries:    opts.Registries,
		CommitTime:    opts.CommitTime,
		Now:           startedAt,
		Filter:        filter,
		PolicyStates:  runState.policyStates,
		SchemaDigests: schemaDigests,
	})
	if err != nil {
		return Result{ExitCode: ExitConfig}, fmt.Errorf("plan: %w", err)
	}
	emitPlanWarnings(opts.Logger, plan, startedAt)

	runRoot := buildRunRoot(plan.Framework, plan.Period.ID, startedAt, runID)
	rec := newRecordingVault(opts.Vault)

	collectOut, err := runCollect(ctx, opts, plan, rec, runRoot, startedAt, retryPolicy)
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
	stampNextDue(results, plan)
	persistResults(ctx, rec, opts.Logger, runRoot, results, runID, plan, completedAt)

	if err := writeManifest(ctx, rec, opts.Logger, runRoot, runID, plan, startedAt, completedAt); err != nil {
		return Result{ExitCode: ExitExecution}, err
	}

	advancePolicyStates(ctx, opts, plan, results, runID, runRoot, startedAt)

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

// runtimeState captures whatever the orchestrator preloaded before
// planning. For ModeScheduled this includes the per-policy state map
// the planner consults for cadence gating. For ModeManual and ModePR
// the map stays nil — those modes always evaluate every in-scope
// policy.
type runtimeState struct {
	policyStates map[string]*core.PolicyState
}

// resolveMode applies the orchestrator Mode to derive the effective
// Filter, slot retry policy, and preloaded runtime state.
//
// When the caller already supplied a cadence-axis filter (Cadences,
// Cadence, or OnPush), the explicit choice wins — mode-derived
// defaults only kick in when no cadence axis was specified. This
// lets a power user combine `--scheduled --policies=foo` to force
// specific policies regardless of cadence state.
func resolveMode(ctx context.Context, opts *Options, _ time.Time) (planner.Filter, collector.RetryPolicy, runtimeState) {
	filter := opts.Filter
	hasExplicitCadence := len(filter.Cadences) > 0 || filter.Cadence != "" || filter.OnPush
	switch opts.Mode {
	case ModePR:
		if !hasExplicitCadence {
			filter.Cadences = []string{core.CadenceOnPush}
		}
		return filter, collector.RetryPR, runtimeState{}
	case ModeScheduled:
		if filter.IsExplicit() {
			// Operator-forced filter: skip state load entirely; every
			// matching policy will evaluate (no cadence gating).
			return filter, collector.RetryScheduled, runtimeState{}
		}
		states := loadPolicyStates(ctx, opts)
		return filter, collector.RetryScheduled, runtimeState{policyStates: states}
	default:
		return filter, collector.RetryNone, runtimeState{}
	}
}

// loadPolicyStates fetches every policy state shard for the
// configured framework. Errors are logged as warnings — a missing
// or unreadable shard degrades to "treat as first run", which is
// safe (the policy re-evaluates) and surfaces loudly via the
// first-run warning at plan time.
func loadPolicyStates(ctx context.Context, opts *Options) map[string]*core.PolicyState {
	framework := opts.Config.Framework
	policies, ok := opts.Registries.Frameworks.Lookup(framework)
	if !ok {
		opts.Logger.Warnf("policy-state: framework %q not yet registered; skipping state load", framework)
		return map[string]*core.PolicyState{}
	}
	ids := make([]string, 0, len(policies.Policies()))
	for _, ref := range policies.Policies() {
		ids = append(ids, ref.PolicyID)
	}
	states, errs := BulkReadPolicyStates(ctx, opts.Vault, framework, ids)
	for _, err := range errs {
		opts.Logger.Warnf("policy-state: %s", err.Error())
	}
	return states
}

// computeSchemaDigests projects every registered evidence type into
// a (type_id → schema_digest) map. The digest is the SHA-256 of the
// canonical JSON encoding of the schema bytes. Used by
// PolicyContentHash so a schema bump invalidates the prior
// evaluation of every policy that references the bumped type.
//
// Returns an empty map when the EvidenceTypes registry is nil or
// empty — content hashing still discriminates policy-spec changes
// in that case, just not schema bumps.
func computeSchemaDigests(set *registry.Set) map[string]string {
	if set == nil || set.EvidenceTypes == nil {
		return nil
	}
	out := make(map[string]string)
	for _, et := range set.EvidenceTypes.All() {
		body, err := json.Marshal(et.Schema)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(body)
		out[et.ID] = "sha256:" + hex.EncodeToString(sum[:])
	}
	return out
}

// stampNextDue computes NextDueAt for each policy result post-
// evaluation. A pass produces NextDueAt = startedAt + interval; any
// other terminal status leaves NextDueAt zero so the planner's
// on_fail_retry rule will fire the next run.
func stampNextDue(results []core.PolicyResult, plan *planner.RunPlan) {
	cadenceByPolicy := make(map[string]string, len(plan.Policies))
	for i := range plan.Policies {
		cadenceByPolicy[plan.Policies[i].Spec.ID] = plan.Policies[i].Cadence
	}
	for i := range results {
		r := &results[i]
		if r.Status != core.StatusPass {
			continue
		}
		cad := cadenceByPolicy[r.PolicyID]
		interval := planner.CadenceInterval(cad)
		if interval == 0 {
			continue
		}
		// Use the run-start-equivalent baseline; we don't have it on the
		// result, but result writes happen close to startedAt so we use
		// the time at which NextDueAt is computed which is the run
		// completion path — close enough for cadence display.
		r.NextDueAt = time.Now().UTC().Add(interval)
	}
}

// emitPlanWarnings surfaces day-1 conditions the operator must see:
// first-run policies (will run now and not again until the cadence
// elapses) and gap-detected (last evaluation was long ago). The
// warnings are explicit so customers don't mistake "all-green on day
// one" for "compliant" — see docs/architecture/11-cadence-model.md
// §Day-1 warnings.
func emitPlanWarnings(logger *log.Logger, plan *planner.RunPlan, now time.Time) {
	if plan == nil {
		return
	}
	var firstRun []string
	var gapped []string
	const gapThreshold = 30 * 24 * time.Hour // 30 days
	for i := range plan.Policies {
		pp := &plan.Policies[i]
		if pp.PriorState == nil || pp.PriorState.IsFirstRun() {
			if pp.ShouldEvaluate {
				firstRun = append(firstRun, pp.Spec.ID)
			}
			continue
		}
		if pp.PriorState.LastRunAt.Before(now.Add(-gapThreshold)) {
			gapped = append(gapped, pp.Spec.ID)
		}
	}
	if len(firstRun) > 0 {
		sort.Strings(firstRun)
		logger.Infof("first-run: %d policies will evaluate for the first time this run", len(firstRun))
		logger.Debugf("first-run policies: %s", strings.Join(firstRun, ", "))
		logger.Infof("first-run: configure a recurring CI schedule before depending on these results")
	}
	if len(gapped) > 0 {
		sort.Strings(gapped)
		logger.Warnf("gap-detected: %d policies have no evaluation in the last 30d; today's run does not backfill", len(gapped))
		logger.Debugf("gap-detected policies: %s", strings.Join(gapped, ", "))
	}
}

// advancePolicyStates writes one state shard per policy that actually
// evaluated in this run. Carry-forward policies keep their existing
// shard untouched. State-write failures are logged as warnings; the
// next run will treat the un-advanced policy as still-due, which is
// the correct degradation (over-run is safe; under-run is not).
func advancePolicyStates(
	ctx context.Context,
	opts *Options,
	plan *planner.RunPlan,
	results []core.PolicyResult,
	runID, runRoot string,
	startedAt time.Time,
) {
	cadenceByPolicy := make(map[string]string, len(plan.Policies))
	hashByPolicy := make(map[string]string, len(plan.Policies))
	for i := range plan.Policies {
		pp := &plan.Policies[i]
		cadenceByPolicy[pp.Spec.ID] = pp.Cadence
		hashByPolicy[pp.Spec.ID] = pp.ContentHash
	}
	for i := range results {
		r := &results[i]
		if r.Status == core.StatusCarriedForward {
			continue
		}
		cadence := cadenceByPolicy[r.PolicyID]
		envelopeRef := ""
		if len(r.EvidenceEnvelopes) > 0 {
			envelopeRef = r.EvidenceEnvelopes[0]
		}
		ps := AdvancePolicyState(
			plan.Framework,
			r.PolicyID,
			runID,
			plan.Period.ID,
			cadence,
			hashByPolicy[r.PolicyID],
			envelopeRef,
			r.Status,
			startedAt,
			planner.CadenceInterval(cadence),
		)
		if err := WritePolicyState(ctx, opts.Vault, ps); err != nil {
			opts.Logger.Warnf("policy-state: write %s: %s", r.PolicyID, err.Error())
		}
	}
	_ = runRoot // reserved for a future per-run state-snapshot file
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

func runCollect(ctx context.Context, opts *Options, plan *planner.RunPlan, rec *recordingVault, runRoot string, now time.Time, retryPolicy collector.RetryPolicy) (*collector.Output, error) {
	out, err := collector.Collect(ctx, &collector.Input{
		Plan:          plan,
		Sources:       opts.Registries.Sources,
		EvidenceTypes: opts.Registries.EvidenceTypes,
		Vault:         rec,
		RunRoot:       runRoot,
		SlotParamsExtras: map[string]any{
			"period_id":       plan.Period.ID,
			"prior_period_id": plan.Period.PriorID,
			"period_start":    plan.Period.Start,
			"period_end":      plan.Period.End,
			"now":             now,
		},
		Now:         now,
		RetryPolicy: retryPolicy,
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

func summaryFromResults(results []core.PolicyResult, runID string, plan *planner.RunPlan, completedAt time.Time) core.FrameworkRunSummary {
	return core.FrameworkRunSummary{
		SchemaVersion: core.RunSummarySchemaVersion,
		RunID:         runID,
		Framework:     plan.Framework,
		PeriodID:      plan.Period.ID,
		CompletedAt:   completedAt,
		Policies:      results,
	}
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
	// Provider names the CI runner ("github_actions", "gitlab_ci"),
	// not the code host. Repository.Provider names the code host
	// ("github", "gitlab"). These are conceptually distinct — a
	// GitHub-hosted repo could in principle run on a non-GitHub CI.
	// The Rails dashboard's CI_PROVIDERS allow-list expects the
	// _actions / _ci suffix; keep these strings in sync.
	if os.Getenv("GITHUB_ACTIONS") != "" {
		runID := os.Getenv("GITHUB_RUN_ID")
		repo := os.Getenv("GITHUB_REPOSITORY")
		var runURL string
		if runID != "" && repo != "" {
			runURL = fmt.Sprintf("https://github.com/%s/actions/runs/%s", repo, runID)
		}
		return core.CIEnvironment{Provider: "github_actions", Workflow: os.Getenv("GITHUB_WORKFLOW"), RunURL: runURL}
	}
	if os.Getenv("GITLAB_CI") != "" {
		return core.CIEnvironment{Provider: "gitlab_ci", Workflow: os.Getenv("CI_JOB_NAME"), RunURL: os.Getenv("CI_JOB_URL")}
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
	var passed, failed, skipped, errored, na, waived, carried int
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
		case core.StatusCarriedForward:
			carried++
		}
	}
	_, _ = fmt.Fprintf(stdout, "SigComply check %s/%s — %d policies\n", plan.Framework, plan.Period.ID, len(results))                                    //nolint:errcheck // status output
	_, _ = fmt.Fprintf(stdout, "  pass=%d fail=%d carried=%d skip=%d error=%d na=%d waived=%d\n", passed, failed, carried, skipped, errored, na, waived) //nolint:errcheck // status output
	sortedResults := make([]core.PolicyResult, len(results))
	copy(sortedResults, results)
	sort.Slice(sortedResults, func(i, j int) bool { return sortedResults[i].PolicyID < sortedResults[j].PolicyID })
	for i := range sortedResults {
		r := &sortedResults[i]
		_, _ = fmt.Fprintf(stdout, "  [%s] %s — %s\n", r.Status, r.PolicyID, core.PrimaryControlID(r.Controls)) //nolint:errcheck // status output
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
	set := registry.NewSet()
	// Evidence-type schemas are loaded before frameworks so policies
	// (which declare slot.Accepts of type IDs) and source plugins
	// (which declare Emits of type IDs) can be checked against the
	// authoritative registry as they register.
	if err := evidencetypes.Register(set); err != nil {
		return nil, nil, fmt.Errorf("bootstrap: register evidence types: %w", err)
	}
	// Data-driven project-local extensions (.sigcomply/evidence_types/*.json,
	// .sigcomply/policies/*/{rule.rego,policy.yaml}) load here, before the
	// caller registers the framework. Go extensions are handled separately
	// at compile time by `sigcomply build`.
	if err := registerProjectLocal(filepath.Dir(configPath), &cfg, set); err != nil {
		return nil, nil, fmt.Errorf("bootstrap: %w", err)
	}
	return &cfg, set, nil
}

// ErrBootstrapAlreadyInitialized is reserved for future use.
var ErrBootstrapAlreadyInitialized = errors.New("orchestrator: already initialized")
