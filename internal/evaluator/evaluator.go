// Package evaluator is L5 of the SigComply CLI: runs each policy's
// rule with the records collected for it and emits PolicyResult.
// Hosts the Rego runner and the Go rule runner; the YAML DSL
// transpiler is deferred (post-M6).
//
// See docs/architecture/02-layers.md.
package evaluator

import (
	"context"
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// Input is the per-run input to Evaluate. RecordsByPolicy is keyed by
// PolicyID; the inner map is keyed by slot name. CollectErrorsByPolicy
// holds collector-side errors (network, auth, schema-validation); a
// non-empty entry forces the policy's status to "error" without invoking
// the rule.
type Input struct {
	Plan                  *planner.RunPlan
	Rules                 *registry.Registry[core.Rule]
	RecordsByPolicy       map[string]map[string][]core.EvidenceRecord
	EnvelopesByPolicy     map[string][]string
	CollectErrorsByPolicy map[string]error
	Now                   time.Time
}

// Evaluate runs the rule for every planned policy and returns the
// per-policy results. Exception suppression (na / waived) is applied
// here so the caller never sees a rule's raw output for a fully-waived
// policy.
func Evaluate(ctx context.Context, in *Input) ([]core.PolicyResult, error) {
	if in == nil || in.Plan == nil {
		return nil, fmt.Errorf("evaluator: nil Input or Plan")
	}
	// Rules registry may be nil when no policy in this run uses a rule: escape hatch.
	// The per-policy evaluation will surface an error for any rule: policy
	// whose registry is nil.
	results := make([]core.PolicyResult, 0, len(in.Plan.Policies))
	for i := range in.Plan.Policies {
		pp := &in.Plan.Policies[i]
		results = append(results, evaluateOne(ctx, pp, in))
	}
	return results, nil
}

func evaluateOne(ctx context.Context, pp *planner.PlannedPolicy, in *Input) core.PolicyResult {
	result := core.PolicyResult{
		PolicyID:          pp.Spec.ID,
		Controls:          pp.Spec.Controls,
		Severity:          pp.Spec.Severity,
		Category:          pp.Spec.Category,
		EffectiveParams:   pp.Parameters,
		EvidenceEnvelopes: in.EnvelopesByPolicy[pp.Spec.ID],
		ConfiguredCadence: pp.Cadence,
		PolicyContentHash: pp.ContentHash,
	}
	// Carry-forward: the planner decided this run does not re-evaluate
	// the policy. Emit a carry-forward result referencing the prior
	// evaluation; an auditor can hash-verify the original envelope
	// from LastEnvelopeRef independently. No rule invocation.
	if !pp.ShouldEvaluate {
		result.Status = core.StatusCarriedForward
		result.CarryForward = buildCarryForwardRef(pp)
		if result.Diag == nil {
			result.Diag = map[string]any{}
		}
		result.Diag["skip_reason"] = pp.SkipReason
		return result
	}
	// Whole-policy exception: na → skip rule entirely; waived without
	// a resource scope → mark waived and skip rule.
	if pp.Exception != nil && pp.Exception.ResourceID == "" && pp.Exception.ResourcePattern == "" {
		result.Status = pp.Exception.State
		return result
	}
	if collectErr := in.CollectErrorsByPolicy[pp.Spec.ID]; collectErr != nil {
		result.Status = core.StatusError
		result.Diag = map[string]any{"collect_error": collectErr.Error()}
		return result
	}
	slots := in.RecordsByPolicy[pp.Spec.ID]

	// Dispatch to the appropriate evaluation path based on evidence_mode.
	var ruleOut core.RuleResult
	switch pp.Spec.EvidenceMode {
	case core.EvidenceModeManual:
		// Path A: universal PDF presence check. No slot population check —
		// the manual check handles missing records explicitly.
		ruleOut = evaluateManual(slots)

	case core.EvidenceModeAutomated:
		if pp.Spec.PassWhen != nil {
			// Path B: pass_when: declarative DSL.
			if !requiredSlotsPopulated(pp, slots) {
				result.Status = core.StatusSkip
				result.Diag = map[string]any{"reason": "required slot has no records"}
				return result
			}
			ruleOut = evaluatePassWhen(pp.Spec.PassWhen, slots, pp.Parameters)
		} else {
			// Path C: rule: escape hatch.
			if !requiredSlotsPopulated(pp, slots) {
				result.Status = core.StatusSkip
				result.Diag = map[string]any{"reason": "required slot has no records"}
				return result
			}
			ruleOut = evaluateRuleRef(ctx, pp, in, slots)
		}

	default:
		// evidence_mode missing or unknown — should have been caught at spec load time.
		result.Status = core.StatusError
		result.Diag = map[string]any{"reason": fmt.Sprintf("policy %q has unrecognized evidence_mode %q", pp.Spec.ID, pp.Spec.EvidenceMode)}
		return result
	}

	result.Status = ruleOut.Status
	result.Violations = ruleOut.Violations
	if ruleOut.Diag != nil {
		result.Diag = ruleOut.Diag
	}
	result.ResourcesEvaluated, result.ResourcesFailed = countResources(slots, ruleOut.Violations)
	applyResourceException(&result, pp.Exception)
	return result
}

func requiredSlotsPopulated(pp *planner.PlannedPolicy, slots map[string][]core.EvidenceRecord) bool {
	for name, slot := range pp.Spec.Slots {
		if !slot.Required {
			continue
		}
		if len(slots[name]) == 0 {
			return false
		}
	}
	return true
}

// countResources returns (evaluated, failed) where evaluated is the sum
// of record counts across all slots and failed is the number of unique
// resource IDs that appear in violations.
func countResources(slots map[string][]core.EvidenceRecord, violations []core.Violation) (evaluated, failed int) {
	for _, recs := range slots {
		evaluated += len(recs)
	}
	failedIDs := map[string]struct{}{}
	for _, v := range violations {
		if v.ResourceID != "" {
			failedIDs[v.ResourceID] = struct{}{}
		}
	}
	failed = len(failedIDs)
	if failed == 0 && len(violations) > 0 {
		// Policy-level failure (no per-resource scope); count it as
		// one logical failure.
		failed = 1
	}
	return evaluated, failed
}

// applyResourceException reclassifies violations matching the
// exception scope. If every violation is suppressed and the policy
// would otherwise have failed, the status becomes waived.
func applyResourceException(result *core.PolicyResult, exc *planner.Exception) {
	if exc == nil {
		return
	}
	if exc.ResourceID == "" && exc.ResourcePattern == "" {
		return
	}
	kept := make([]core.Violation, 0, len(result.Violations))
	waived := 0
	for _, v := range result.Violations {
		if matchesScope(v.ResourceID, exc) {
			waived++
			continue
		}
		kept = append(kept, v)
	}
	result.Violations = kept
	if waived > 0 && len(kept) == 0 && result.Status == core.StatusFail {
		result.Status = core.StatusWaived
	}
	if waived > 0 {
		if result.Diag == nil {
			result.Diag = map[string]any{}
		}
		result.Diag["waived_count"] = waived
	}
	// Recompute counts.
	if result.ResourcesFailed >= waived {
		result.ResourcesFailed -= waived
	}
}

// buildCarryForwardRef captures the prior evaluation pointers a
// carry-forward result needs. PriorState may be nil when this is the
// first plan after introducing a new policy whose cadence has not
// yet elapsed (rare — first runs are always ShouldEvaluate=true) or
// for tests that don't load state; the returned ref handles both
// cases gracefully.
func buildCarryForwardRef(pp *planner.PlannedPolicy) *core.CarryForwardRef {
	ref := &core.CarryForwardRef{SkipReason: pp.SkipReason}
	if pp.PriorState == nil {
		return ref
	}
	ref.LastEvaluatedAt = pp.PriorState.LastRunAt
	ref.LastEnvelopeRef = pp.PriorState.LastEnvelopeRef
	ref.LastKnownStatus = pp.PriorState.LastRunStatus
	// LastEvaluatedRun is the run-relative root that the envelope ref
	// is relative to. Currently the envelope ref stored in state is
	// already a full vault path; LastEvaluatedRun stays empty until a
	// future refactor splits the two. The auditor flow only needs
	// LastEnvelopeRef to verify.
	return ref
}

func matchesScope(resourceID string, exc *planner.Exception) bool {
	if exc.ResourceID != "" && resourceID == exc.ResourceID {
		return true
	}
	if exc.ResourcePattern == "" {
		return false
	}
	// Simple suffix-wildcard support, matching the planner's
	// policy-pattern semantics. Exact prefix matching is sufficient for
	// the M6 walking skeleton; richer matching is post-M6.
	if exc.ResourcePattern != "" && exc.ResourcePattern[len(exc.ResourcePattern)-1] == '*' {
		prefix := exc.ResourcePattern[:len(exc.ResourcePattern)-1]
		return len(resourceID) >= len(prefix) && resourceID[:len(prefix)] == prefix
	}
	return resourceID == exc.ResourcePattern
}

// evaluateRuleRef handles Path C (rule: escape hatch) for automated policies.
// It looks up the rule in the registry and invokes it, returning a RuleResult
// with status=error when the registry is nil, the rule is unregistered, or
// the rule returns an error.
func evaluateRuleRef(ctx context.Context, pp *planner.PlannedPolicy, in *Input, slots map[string][]core.EvidenceRecord) core.RuleResult {
	if in.Rules == nil {
		return core.RuleResult{Status: core.StatusError, Diag: map[string]any{"reason": "rule registry is nil; cannot evaluate rule: policy"}}
	}
	rule, ok := in.Rules.Lookup(pp.Spec.RuleRef)
	if !ok {
		return core.RuleResult{Status: core.StatusError, Diag: map[string]any{"reason": fmt.Sprintf("rule %q not registered", pp.Spec.RuleRef)}}
	}
	ruleOut, err := rule.Evaluate(ctx, core.RuleInput{
		PolicyID: pp.Spec.ID,
		Slots:    slots,
		Params:   pp.Parameters,
		Now:      in.Now,
	})
	if err != nil {
		return core.RuleResult{Status: core.StatusError, Diag: map[string]any{"rule_error": err.Error()}}
	}
	return ruleOut
}
