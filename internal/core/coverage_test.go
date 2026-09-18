package core_test

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func auto(id, control string) core.Policy {
	return core.Policy{ID: id, EvidenceMode: core.EvidenceModeAutomated, Controls: []core.ControlRef{{ControlID: control}}}
}

func manual(id, control string) core.Policy {
	return core.Policy{ID: id, EvidenceMode: core.EvidenceModeManual, Controls: []core.ControlRef{{ControlID: control}}}
}

func TestClassifyControls(t *testing.T) {
	controls := []core.Control{{ID: "CC2.1"}, {ID: "CC1.1"}, {ID: "CC6.1"}, {ID: "CC9.9"}}
	policies := []core.Policy{
		auto("a1", "CC6.1"),
		manual("m1", "CC6.1"), // a control can hold both; the automated check wins
		manual("m2", "CC1.1"),
		manual("m3", "CC1.1"),
		auto("a2", "CC2.1"),
	}

	got := core.ClassifyControls(controls, policies)

	if len(got) != 4 {
		t.Fatalf("got %d rows; want one per declared control (4)", len(got))
	}
	// Sorted by control ID, so the output is stable across runs.
	want := []string{"CC1.1", "CC2.1", "CC6.1", "CC9.9"}
	for i, id := range want {
		if got[i].ControlID != id {
			t.Fatalf("row %d = %q; want %q (rows must sort by control ID)", i, got[i].ControlID, id)
		}
	}

	byID := map[string]core.ControlCoverage{}
	for _, c := range got {
		byID[c.ControlID] = c
	}

	if c := byID["CC6.1"]; c.Assurance != core.AssuranceAutomated || c.AutomatedPolicies != 1 || c.ManualPolicies != 1 {
		t.Errorf("CC6.1 = %+v; want automated with 1 automated + 1 manual policy — one real check outranks any number of documents", c)
	}
	if c := byID["CC1.1"]; c.Assurance != core.AssuranceManual || c.ManualPolicies != 2 {
		t.Errorf("CC1.1 = %+v; want manual with 2 manual policies", c)
	}
	if c := byID["CC2.1"]; c.Assurance != core.AssuranceAutomated {
		t.Errorf("CC2.1 = %+v; want automated", c)
	}
	if c := byID["CC9.9"]; c.Assurance != core.AssuranceNone || c.AutomatedPolicies != 0 || c.ManualPolicies != 0 {
		t.Errorf("CC9.9 = %+v; want none — a control nothing implements must stay visible, not vanish", c)
	}
}

// TestClassifyControls_IgnoresPoliciesForUnknownControls keeps a policy
// pointing at a control the framework does not declare from inventing a
// row. The reverse direction (a declared control with no policy) is
// covered by AssuranceNone above and guarded at build time by
// TestEveryControlHasAPolicy.
func TestClassifyControls_IgnoresPoliciesForUnknownControls(t *testing.T) {
	got := core.ClassifyControls(
		[]core.Control{{ID: "CC1.1"}},
		[]core.Policy{auto("a1", "CC1.1"), auto("a2", "NOT-A-CONTROL")},
	)
	if len(got) != 1 {
		t.Fatalf("got %d rows; want 1 — only declared controls get a row", len(got))
	}
	if got[0].AutomatedPolicies != 1 {
		t.Errorf("AutomatedPolicies = %d; want 1", got[0].AutomatedPolicies)
	}
}

func TestCoverageTotals(t *testing.T) {
	rows := []core.ControlCoverage{
		{ControlID: "A", Assurance: core.AssuranceAutomated},
		{ControlID: "B", Assurance: core.AssuranceManual},
		{ControlID: "C", Assurance: core.AssuranceManual},
		{ControlID: "D", Assurance: core.AssuranceNone},
	}
	tot := core.CoverageTotals(rows)
	if tot.Controls != 4 || tot.Automated != 1 || tot.Manual != 2 || tot.Uncovered != 1 {
		t.Errorf("CoverageTotals = %+v; want {Controls:4 Automated:1 Manual:2 Uncovered:1}", tot)
	}
}
