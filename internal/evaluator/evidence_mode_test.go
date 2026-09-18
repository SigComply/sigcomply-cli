package evaluator_test

import (
	"context"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// TestEvaluate_RecordsEffectiveEvidenceMode pins the fact that every
// result says how it was reached.
//
// Why this matters: a manual policy passes when a PDF is present in the
// right folder, in the window, and parseable — its contents are never
// read. An automated policy passes after inspecting live infrastructure.
// Both emit StatusPass, and nothing downstream — not the vault, not the
// report, not the dashboard — could tell them apart, so a run whose
// controls rest entirely on uploaded documents was indistinguishable
// from one that verified everything.
func TestEvaluate_RecordsEffectiveEvidenceMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode core.EvidenceMode
	}{
		{"automated", core.EvidenceModeAutomated},
		{"manual", core.EvidenceModeManual},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := &planner.RunPlan{Policies: []planner.PlannedPolicy{{
				Spec: core.Policy{
					ID:           "p1",
					EvidenceMode: tc.mode,
					Controls:     []core.ControlRef{{ControlID: "CC6.1"}},
				},
				ShouldEvaluate: true,
			}}}
			results, err := evaluator.Evaluate(context.Background(), &evaluator.Input{Plan: plan})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("got %d results; want 1", len(results))
			}
			if got := results[0].EvidenceMode; got != tc.mode {
				t.Errorf("EvidenceMode = %q; want %q", got, tc.mode)
			}
			if results[0].EvidenceModeOverridden {
				t.Errorf("EvidenceModeOverridden = true; want false for a policy the project did not override")
			}
		})
	}
}

// TestEvaluate_RecordsEvidenceModeOverride closes a gap that was
// documented but never implemented: internal/planner computed
// EvidenceModeOverridden and its doc comment claimed the flag was
// "surfaced in result.json so auditors can see which policies are
// running in an overridden mode". Nothing read it.
//
// A project can downgrade an automated check to "we will upload a
// document instead" via the policy override in .sigcomply.yaml. That is
// a legitimate escape hatch, but until now no artifact anywhere recorded
// that it happened — control degradation with no trail, in a product
// whose vault exists to make exactly that impossible.
func TestEvaluate_RecordsEvidenceModeOverride(t *testing.T) {
	plan := &planner.RunPlan{Policies: []planner.PlannedPolicy{{
		Spec: core.Policy{
			ID:           "p1",
			EvidenceMode: core.EvidenceModeManual,
			CatalogEntry: "some_entry",
			Controls:     []core.ControlRef{{ControlID: "CC6.1"}},
		},
		EvidenceModeOverridden: true,
		ShouldEvaluate:         true,
	}}}
	results, err := evaluator.Evaluate(context.Background(), &evaluator.Input{Plan: plan})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !results[0].EvidenceModeOverridden {
		t.Error("EvidenceModeOverridden = false; want true — the project overrode this policy's evidence mode")
	}
	if got := results[0].EvidenceMode; got != core.EvidenceModeManual {
		t.Errorf("EvidenceMode = %q; want the effective mode %q, not the framework default", got, core.EvidenceModeManual)
	}
}

// TestEvaluate_CarriedForwardRecordsEvidenceMode covers the row kind
// that never reaches a rule at all. A carry-forward result still stands
// for a control in every report, so it must carry the same provenance.
func TestEvaluate_CarriedForwardRecordsEvidenceMode(t *testing.T) {
	plan := &planner.RunPlan{Policies: []planner.PlannedPolicy{{
		Spec: core.Policy{
			ID:           "p1",
			EvidenceMode: core.EvidenceModeManual,
			Controls:     []core.ControlRef{{ControlID: "CC1.1"}},
		},
		ShouldEvaluate: false,
		SkipReason:     "cadence not elapsed",
	}}}
	results, err := evaluator.Evaluate(context.Background(), &evaluator.Input{Plan: plan})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Status != core.StatusCarriedForward {
		t.Fatalf("Status = %q; want carried_forward", results[0].Status)
	}
	if got := results[0].EvidenceMode; got != core.EvidenceModeManual {
		t.Errorf("EvidenceMode = %q; want %q on a carried-forward row too", got, core.EvidenceModeManual)
	}
}
