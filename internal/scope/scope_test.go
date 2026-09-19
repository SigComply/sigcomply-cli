package scope_test

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/scope"
)

const (
	testSlotUsers    = "users"
	testSourceAWSIAM = "aws.iam"
	testSourceGitHub = "github"
	testSourceOkta   = "okta"
	testSourceAlpha  = "alpha"
	testSourceMid    = "mid"
	testSourceZeta   = "zeta"
)

func planWith(bindings map[string][]planner.Binding, unbound []string) *planner.RunPlan {
	return &planner.RunPlan{Policies: []planner.PlannedPolicy{{
		Spec:                 core.Policy{ID: "p1"},
		Bindings:             bindings,
		UnboundRequiredSlots: unbound,
	}}}
}

func recordsFrom(sourceIDs ...string) map[string]map[string][]core.EvidenceRecord {
	recs := make([]core.EvidenceRecord, 0, len(sourceIDs))
	for _, id := range sourceIDs {
		recs = append(recs, core.EvidenceRecord{SourceID: id})
	}
	return map[string]map[string][]core.EvidenceRecord{"p1": {testSlotUsers: recs}}
}

func TestEvaluate_Undeclared(t *testing.T) {
	got := scope.Evaluate(&scope.Input{
		Configured: map[string]map[string]any{testSourceAWSIAM: {}},
		Plan:       planWith(nil, []string{testSlotUsers}),
	})
	if got.Status != scope.StatusUndeclared {
		t.Errorf("Status = %q; want undeclared", got.Status)
	}
	// The unbound count is informative on its own and must be reported
	// even with no declaration to judge against.
	if got.PoliciesUnbound != 1 {
		t.Errorf("PoliciesUnbound = %d; want 1", got.PoliciesUnbound)
	}
	if !got.Complete() {
		t.Error("Complete() = false; an undeclared estate cannot fall short")
	}
}

func TestEvaluate_Complete(t *testing.T) {
	got := scope.Evaluate(&scope.Input{
		Declared:        []string{testSourceAWSIAM, testSourceGitHub},
		Configured:      map[string]map[string]any{testSourceAWSIAM: {}, testSourceGitHub: {}},
		Plan:            planWith(map[string][]planner.Binding{testSlotUsers: {{SourceID: testSourceAWSIAM}, {SourceID: testSourceGitHub}}}, nil),
		RecordsByPolicy: recordsFrom(testSourceAWSIAM, testSourceGitHub),
	})
	if got.Status != scope.StatusComplete {
		t.Fatalf("Status = %q; want complete (sources=%+v)", got.Status, got.Sources)
	}
	if len(got.Missing) != 0 {
		t.Errorf("Missing = %v; want none", got.Missing)
	}
	if !got.Complete() {
		t.Error("Complete() = false")
	}
}

// The three ways a declared source fails to count. Stopping at
// "is it in sources:?" would pass all three.
func TestEvaluate_ClassifiesEachFailure(t *testing.T) {
	cases := []struct {
		name  string
		in    *scope.Input
		want  scope.SourceState
		which string
	}{
		{
			name: "declared but absent from sources:",
			in: &scope.Input{
				Declared:   []string{testSourceOkta},
				Configured: map[string]map[string]any{testSourceAWSIAM: {}},
				Plan:       planWith(map[string][]planner.Binding{testSlotUsers: {{SourceID: testSourceAWSIAM}}}, nil),
			},
			want:  scope.SourceNotConfigured,
			which: testSourceOkta,
		},
		{
			name: "configured but no slot bound it",
			in: &scope.Input{
				Declared:   []string{testSourceOkta},
				Configured: map[string]map[string]any{testSourceOkta: {}},
				Plan:       planWith(map[string][]planner.Binding{testSlotUsers: {{SourceID: testSourceAWSIAM}}}, nil),
			},
			want:  scope.SourceNotBound,
			which: testSourceOkta,
		},
		{
			name: "bound but returned nothing",
			in: &scope.Input{
				Declared:        []string{testSourceOkta},
				Configured:      map[string]map[string]any{testSourceOkta: {}},
				Plan:            planWith(map[string][]planner.Binding{testSlotUsers: {{SourceID: testSourceOkta}}}, nil),
				RecordsByPolicy: recordsFrom(),
			},
			want:  scope.SourceNoRecords,
			which: testSourceOkta,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scope.Evaluate(c.in)
			if got.Status != scope.StatusIncomplete {
				t.Fatalf("Status = %q; want incomplete", got.Status)
			}
			if got.Complete() {
				t.Error("Complete() = true; want false")
			}
			if len(got.Sources) != 1 || got.Sources[0].State != c.want {
				t.Fatalf("Sources = %+v; want state %q", got.Sources, c.want)
			}
			if len(got.Missing) != 1 || got.Missing[0] != c.which {
				t.Errorf("Missing = %v; want [%s]", got.Missing, c.which)
			}
		})
	}
}

// Auditors diff runs (Core Principle #7), so output ordering must not
// depend on map iteration order.
func TestEvaluate_Deterministic(t *testing.T) {
	in := &scope.Input{
		Declared:   []string{testSourceZeta, testSourceAlpha, testSourceMid},
		Configured: map[string]map[string]any{testSourceMid: {}},
		Plan:       planWith(map[string][]planner.Binding{testSlotUsers: {{SourceID: testSourceMid}}}, nil),
	}
	for i := 0; i < 20; i++ {
		got := scope.Evaluate(in)
		if got.Sources[0].SourceID != testSourceAlpha || got.Sources[1].SourceID != testSourceMid || got.Sources[2].SourceID != testSourceZeta {
			t.Fatalf("Sources not sorted: %+v", got.Sources)
		}
		// All three fall short here: alpha/zeta are unconfigured, and mid
		// is configured and bound but produced no records.
		if len(got.Missing) != 3 || got.Missing[0] != testSourceAlpha || got.Missing[1] != testSourceMid || got.Missing[2] != testSourceZeta {
			t.Fatalf("Missing not sorted: %v", got.Missing)
		}
	}
}

func TestEvaluate_AuditTrailPassedThrough(t *testing.T) {
	got := scope.Evaluate(&scope.Input{
		Declared:        []string{testSourceGitHub},
		DeclaredBy:      "ciso@example.com",
		DeclaredAt:      "2026-09-13",
		Configured:      map[string]map[string]any{testSourceGitHub: {}},
		Plan:            planWith(map[string][]planner.Binding{"repos": {{SourceID: testSourceGitHub}}}, nil),
		RecordsByPolicy: recordsFrom(testSourceGitHub),
	})
	if got.DeclaredBy != "ciso@example.com" || got.DeclaredAt != "2026-09-13" {
		t.Errorf("audit trail = %q/%q", got.DeclaredBy, got.DeclaredAt)
	}
}

func TestReport_NilIsComplete(t *testing.T) {
	var r *scope.Report
	if !r.Complete() {
		t.Error("nil Report must be Complete")
	}
}
