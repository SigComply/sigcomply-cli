package planner

import (
	"fmt"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Input collects everything the planner needs to compute a Plan.
// CommitTime is the basis for period derivation; pass commit time
// when time_basis == "commit" (the default) and wall-clock when
// the project opts into wall_clock.
//
// PolicyStates is keyed by policy_id and provides the per-policy
// scheduling state read from the vault. A nil map disables cadence
// gating: every policy in the framework will have ShouldEvaluate
// set to true. A non-nil map enables gating: each policy's
// ShouldEvaluate decision composes its cadence, prior status,
// content-hash, and the operator's filter.
//
// SchemaDigests maps evidence-type IDs to their JSON Schema digests
// at plan time. Used by PolicyContentHash so a schema bump
// invalidates prior evaluations of every policy referencing the
// bumped schema. Pass nil to disable schema-hash discrimination
// (the policy-spec content still contributes to the hash).
type Input struct {
	Config        *spec.ProjectConfig
	Registries    *registry.Set
	CommitTime    time.Time
	Now           time.Time
	Filter        Filter
	PolicyStates  map[string]*core.PolicyState
	SchemaDigests map[string]string
}

// Filter narrows the set of policies the plan covers. The five
// fields are mutually exclusive — passing more than one yields an
// error. Filter{} means "every policy in the framework."
//
// Cadences is the canonical "fire when these cadences are due" filter
// — set-intersection against core.PolicyCadences(policy). It is the
// shape the orchestrator's PR and Scheduled modes use. Cadence and
// OnPush remain as legacy single-axis shortcuts; they translate to
// single-element Cadences sets internally.
//
// When any field is set, all matching policies receive
// ShouldEvaluate=true regardless of cadence state. The filter is the
// operator's explicit override — "I want these to run now" — and
// trumps the planner's cadence-elapsed gate.
type Filter struct {
	Policies []string
	Controls []string
	Cadence  string
	OnPush   bool
	Cadences []string
}

// IsExplicit returns true when at least one filter axis is set. An
// explicit filter forces ShouldEvaluate=true for every matching
// policy — the user said "run these now."
func (f *Filter) IsExplicit() bool {
	return len(f.Policies) > 0 ||
		len(f.Controls) > 0 ||
		f.Cadence != "" ||
		f.OnPush ||
		len(f.Cadences) > 0
}

// Plan computes the run plan. Errors surface back to the orchestrator
// as exit-code-3 conditions. No I/O happens here.
func Plan(in *Input) (*RunPlan, error) {
	if err := validateFilter(&in.Filter); err != nil {
		return nil, err
	}
	framework, ok := in.Registries.Frameworks.Lookup(in.Config.Framework)
	if !ok {
		return nil, fmt.Errorf("planner: framework %q not registered", in.Config.Framework)
	}
	period, err := DerivePeriod(&in.Config.Period, in.CommitTime)
	if err != nil {
		return nil, err
	}
	policies, err := planPolicies(framework, in)
	if err != nil {
		return nil, err
	}
	return &RunPlan{
		Framework: framework.ID(),
		Period:    period,
		Policies:  policies,
	}, nil
}

func validateFilter(f *Filter) error {
	count := 0
	if len(f.Policies) > 0 {
		count++
	}
	if len(f.Controls) > 0 {
		count++
	}
	if f.Cadence != "" {
		count++
	}
	if f.OnPush {
		count++
	}
	if len(f.Cadences) > 0 {
		count++
	}
	if count > 1 {
		return fmt.Errorf("planner: --policies, --controls, --cadence, --on-push, --cadences are mutually exclusive (set %d of them)", count)
	}
	return nil
}

func planPolicies(framework core.Framework, in *Input) ([]PlannedPolicy, error) {
	// The framework's own policies plus any project-local policies
	// discovered at bootstrap (.sigcomply/policies/*/policy.yaml). One
	// project = one framework, so every project-local policy belongs to
	// the active framework. Dedupe by ID so a project-local policy reusing
	// a framework policy ID is planned once.
	refs := framework.Policies()
	if in.Config != nil {
		refs = append(refs, in.Config.ProjectLocalPolicies...)
	}
	planned := make([]PlannedPolicy, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if _, dup := seen[ref.PolicyID]; dup {
			continue
		}
		seen[ref.PolicyID] = struct{}{}
		policy, ok := in.Registries.Policies.Lookup(ref.PolicyID)
		if !ok {
			return nil, fmt.Errorf("planner: framework %q references unknown policy %q", framework.ID(), ref.PolicyID)
		}
		if !filterAccepts(&policy, &in.Filter, in.Config.PolicyCadences) {
			continue
		}
		pp, err := planOne(&policy, in)
		if err != nil {
			return nil, err
		}
		planned = append(planned, pp)
	}
	return planned, nil
}

func planOne(policy *core.Policy, in *Input) (PlannedPolicy, error) {
	// Apply project-level evidence_mode override before binding resolution.
	// Work on a local copy so we never mutate the registry entry.
	originalMode := policy.EvidenceMode
	p := applyEvidenceModeOverride(policy, in.Config.PolicyOverrides)
	policy = &p

	overrides := in.Config.PolicyParameters[policy.ID]
	params, err := resolveParameters(policy, overrides)
	if err != nil {
		return PlannedPolicy{}, err
	}
	var bindings map[string][]Binding
	var coverageGaps []CoverageGap
	if policy.EvidenceMode == core.EvidenceModeManual {
		// Manual policies have no configurable slots. The planner creates a
		// synthetic "_manual" binding pointing to the manual.pdf singleton,
		// which the collector resolves via the catalog entry. Any project-config
		// bindings for this policy are a configuration error.
		if len(in.Config.Bindings[policy.ID]) > 0 {
			return PlannedPolicy{}, fmt.Errorf("planner: policy %q (evidence_mode: manual) must not declare bindings in project config", policy.ID)
		}
		bindings = resolveManualBinding(policy)
	} else {
		bindings, err = resolveBindings(policy, in.Config.Bindings[policy.ID], in.Registries.Sources)
		if err != nil {
			return PlannedPolicy{}, err
		}
		coverageGaps = detectCoverageGaps(policy, bindings, in.Config.Sources, in.Registries.Sources)
	}
	exception := resolveException(policy.ID, in.Config.Exceptions, in.Now)
	cadence := resolveCadence(policy.ID, policy.Cadence, in.Config.PolicyCadences)

	contentHash := core.PolicyContentHash(policy, in.SchemaDigests)
	priorState := lookupState(in.PolicyStates, policy.ID)
	shouldEvaluate, skipReason := decideEvaluation(&in.Filter, cadence, contentHash, priorState, in.Now)

	return PlannedPolicy{
		Spec:                   *policy,
		Cadence:                cadence,
		Parameters:             params,
		Bindings:               bindings,
		Exception:              exception,
		ShouldEvaluate:         shouldEvaluate,
		SkipReason:             skipReason,
		EvidenceModeOverridden: policy.EvidenceMode != originalMode,
		CoverageGaps:           coverageGaps,
		PriorState:             priorState,
		ContentHash:            contentHash,
	}, nil
}

// decideEvaluation is the per-policy gate. Returns (ShouldEvaluate,
// SkipReason). The decision is layered:
//
//  1. Explicit operator filter (--policies, --cadences, --on-push)
//     → forced evaluation; cadence gating is bypassed entirely.
//  2. PolicyStates absent (nil map) → no gating; evaluate.
//  3. Content-hash mismatch → bundle update or schema bump invalidated
//     prior evaluation; evaluate.
//  4. Cadence elapsed via planner.IsDue (which also handles
//     on_fail_retry and first-run) → evaluate.
//  5. Otherwise → carry forward; SkipReason explains why.
func decideEvaluation(filter *Filter, cadence, contentHash string, prior *core.PolicyState, now time.Time) (shouldEvaluate bool, skipReason string) {
	if filter.IsExplicit() {
		return true, ""
	}
	if prior == nil {
		return true, ""
	}
	if contentHash != "" && prior.LastPolicyHash != "" && contentHash != prior.LastPolicyHash {
		return true, "policy bundle or referenced schema changed since last evaluation; content_hash mismatch"
	}
	if IsDue(cadence, prior, now) {
		return true, ""
	}
	return false, DueReason(cadence, prior, now)
}

func lookupState(states map[string]*core.PolicyState, policyID string) *core.PolicyState {
	if states == nil {
		return nil
	}
	if ps, ok := states[policyID]; ok {
		return ps
	}
	return nil
}

// policyMatchesControl reports whether any of the policy's controls has
// a ControlID listed in wanted. A policy can map to controls across
// frameworks; the --controls operator filter matches on any of them.
func policyMatchesControl(policy *core.Policy, wanted []string) bool {
	for i := range policy.Controls {
		if containsString(wanted, policy.Controls[i].ControlID) {
			return true
		}
	}
	return false
}

func filterAccepts(policy *core.Policy, f *Filter, cadenceOverrides map[string]string) bool {
	if len(f.Policies) > 0 {
		return containsString(f.Policies, policy.ID)
	}
	if len(f.Controls) > 0 {
		return policyMatchesControl(policy, f.Controls)
	}
	if len(f.Cadences) > 0 {
		return policyMatchesCadences(policy, f.Cadences, cadenceOverrides)
	}
	if f.Cadence != "" {
		effective := resolveCadence(policy.ID, policy.Cadence, cadenceOverrides)
		return effective == f.Cadence
	}
	if f.OnPush {
		return policy.OnPush
	}
	return true
}

// policyMatchesCadences returns true if the policy's effective cadence
// set (its overridden Cadence plus CadenceOnPush when OnPush) shares
// at least one element with filterCadences.
func policyMatchesCadences(policy *core.Policy, filterCadences []string, cadenceOverrides map[string]string) bool {
	effective := resolveCadence(policy.ID, policy.Cadence, cadenceOverrides)
	wanted := make(map[string]struct{}, len(filterCadences))
	for _, c := range filterCadences {
		wanted[c] = struct{}{}
	}
	if _, ok := wanted[effective]; ok {
		return true
	}
	if policy.OnPush {
		if _, ok := wanted[core.CadenceOnPush]; ok {
			return true
		}
	}
	return false
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

// resolveManualBinding creates the synthetic binding for a manual policy.
// The collector uses the "_manual" slot name to route to the manual.pdf
// source; the CatalogID drives path resolution inside the plugin.
func resolveManualBinding(policy *core.Policy) map[string][]Binding {
	return map[string][]Binding{
		spec.ManualSlotName: {{
			SourceID:      "manual.pdf",
			AcceptedTypes: []string{"signed_document"},
			CatalogID:     policy.CatalogEntry,
		}},
	}
}

// applyEvidenceModeOverride returns a copy of p with EvidenceMode and
// CatalogEntry patched from overrides[p.ID]. Returns a plain copy of p
// unchanged when no override is declared for this policy. Takes p by
// pointer to avoid copying 216 bytes on the hot path; always makes an
// explicit value copy before mutating.
func applyEvidenceModeOverride(p *core.Policy, overrides map[string]spec.PolicyOverride) core.Policy {
	o, ok := overrides[p.ID]
	if !ok {
		return *p
	}
	cp := *p
	cp.EvidenceMode = core.EvidenceMode(o.EvidenceMode)
	cp.CatalogEntry = o.CatalogEntry
	return cp
}

// SplitCommaList is a small helper for the orchestrator: turn a
// comma-separated CLI flag value into a trimmed list.
func SplitCommaList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
