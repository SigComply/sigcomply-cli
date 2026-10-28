package evaluator

import (
	"context"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

const (
	testTypeTrail = "audit_log_trail"
	slotEvidence  = "evidence"
)

// presencePolicy is a pass_when policy over one slot, the shape every
// shipped presence policy has.
func presencePolicy(failWhenEmpty, bound bool) planner.PlannedPolicy {
	pp := planner.PlannedPolicy{
		Spec: core.Policy{
			ID:           "p.presence",
			Controls:     []core.ControlRef{{ControlID: "CC7.1"}},
			Severity:     core.SeverityHigh,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{slotEvidence: {
				Accepts: []string{testTypeTrail}, Cardinality: core.SlotOneOrMore, Required: true,
				Description: "audit logging", FailWhenEmpty: failWhenEmpty,
			}},
			PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot: slotEvidence, Quantifier: core.QuantifierAll,
				Condition: &core.PassWhenCondition{Op: "eq", Field: "payload.is_enabled", Value: true},
			}}},
		},
		ShouldEvaluate: true,
	}
	if bound {
		pp.Bindings = map[string][]planner.Binding{slotEvidence: {{SourceID: "aws.cloudtrail", AcceptedTypes: []string{testTypeTrail}}}}
	}
	return pp
}

func evaluatePresence(t *testing.T, pp *planner.PlannedPolicy) core.PolicyResult {
	t.Helper()
	res, err := Evaluate(context.Background(), &Input{
		Plan:            &planner.RunPlan{Policies: []planner.PlannedPolicy{*pp}},
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{pp.Spec.ID: {slotEvidence: nil}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res[0]
}

// A bound presence source that answered "nothing exists" is the gap the
// policy asks about: it fails, and counts as one failed resource so the
// wire message does not read "0 of 0 resources failed".
func TestEvaluate_FailWhenEmpty_BoundEmptySourceFails(t *testing.T) {
	pp := presencePolicy(true, true)
	got := evaluatePresence(t, &pp)
	if got.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail", got.Status)
	}
	want := "no audit_log_trail records: audit logging not enabled or not found"
	if got.Diag[diagReason] != want {
		t.Errorf("diag reason = %v; want %q", got.Diag[diagReason], want)
	}
	if len(got.Violations) != 1 || got.Violations[0].Reason != want {
		t.Errorf("violations = %+v; want one policy-level violation with the reason", got.Violations)
	}
	if got.ResourcesFailed != 1 || got.ResourcesEvaluated != 0 {
		t.Errorf("counts = %d evaluated, %d failed; want 0, 1", got.ResourcesEvaluated, got.ResourcesFailed)
	}
}

// For-all policies keep skipping on an empty source: "every trail is
// encrypted" says nothing about an estate with no trail.
func TestEvaluate_ForAllEmptySourceStillSkips(t *testing.T) {
	pp := presencePolicy(false, true)
	got := evaluatePresence(t, &pp)
	if got.Status != core.StatusSkip {
		t.Fatalf("status = %q; want skip", got.Status)
	}
}

// No source behind the slot means nothing was asked, so even a presence
// policy skips.
func TestEvaluate_FailWhenEmpty_UnboundSlotSkips(t *testing.T) {
	pp := presencePolicy(true, false)
	got := evaluatePresence(t, &pp)
	if got.Status != core.StatusSkip {
		t.Fatalf("status = %q; want skip", got.Status)
	}
	if got.Diag[diagReason] != "no source bound to any slot" {
		t.Errorf("diag reason = %v", got.Diag[diagReason])
	}
}

// A waiver or exception still applies to the policy-level failure.
func TestEvaluate_FailWhenEmpty_WholePolicyWaiverWins(t *testing.T) {
	pp := presencePolicy(true, true)
	pp.Exceptions = []*planner.Exception{{State: core.StatusWaived, Reason: "accepted"}}
	if got := evaluatePresence(t, &pp); got.Status != core.StatusWaived {
		t.Fatalf("status = %q; want waived", got.Status)
	}
}
