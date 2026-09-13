package scope_test

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/scope"
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
	return map[string]map[string][]core.EvidenceRecord{"p1": {"users": recs}}
}

func TestEvaluate_Undeclared(t *testing.T) {
	got := scope.Evaluate(&scope.Input{
		Configured: map[string]map[string]any{"aws.iam": {}},
		Plan:       planWith(nil, []string{"users"}),
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
		Declared:        []string{"aws.iam", "github"},
		Configured:      map[string]map[string]any{"aws.iam": {}, "github": {}},
		Plan:            planWith(map[string][]planner.Binding{"users": {{SourceID: "aws.iam"}, {SourceID: "github"}}}, nil),
		RecordsByPolicy: recordsFrom("aws.iam", "github"),
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
				Declared:   []string{"okta"},
				Configured: map[string]map[string]any{"aws.iam": {}},
				Plan:       planWith(map[string][]planner.Binding{"users": {{SourceID: "aws.iam"}}}, nil),
			},
			want:  scope.SourceNotConfigured,
			which: "okta",
		},
		{
			name: "configured but no slot bound it",
			in: &scope.Input{
				Declared:   []string{"okta"},
				Configured: map[string]map[string]any{"okta": {}},
				Plan:       planWith(map[string][]planner.Binding{"users": {{SourceID: "aws.iam"}}}, nil),
			},
			want:  scope.SourceNotBound,
			which: "okta",
		},
		{
			name: "bound but returned nothing",
			in: &scope.Input{
				Declared:        []string{"okta"},
				Configured:      map[string]map[string]any{"okta": {}},
				Plan:            planWith(map[string][]planner.Binding{"users": {{SourceID: "okta"}}}, nil),
				RecordsByPolicy: recordsFrom(),
			},
			want:  scope.SourceNoRecords,
			which: "okta",
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
		Declared:   []string{"zeta", "alpha", "mid"},
		Configured: map[string]map[string]any{"mid": {}},
		Plan:       planWith(map[string][]planner.Binding{"users": {{SourceID: "mid"}}}, nil),
	}
	for i := 0; i < 20; i++ {
		got := scope.Evaluate(in)
		if got.Sources[0].SourceID != "alpha" || got.Sources[1].SourceID != "mid" || got.Sources[2].SourceID != "zeta" {
			t.Fatalf("Sources not sorted: %+v", got.Sources)
		}
		// All three fall short here: alpha/zeta are unconfigured, and mid
		// is configured and bound but produced no records.
		if len(got.Missing) != 3 || got.Missing[0] != "alpha" || got.Missing[1] != "mid" || got.Missing[2] != "zeta" {
			t.Fatalf("Missing not sorted: %v", got.Missing)
		}
	}
}

func TestEvaluate_AuditTrailPassedThrough(t *testing.T) {
	got := scope.Evaluate(&scope.Input{
		Declared:        []string{"github"},
		DeclaredBy:      "ciso@example.com",
		DeclaredAt:      "2026-09-13",
		Configured:      map[string]map[string]any{"github": {}},
		Plan:            planWith(map[string][]planner.Binding{"repos": {{SourceID: "github"}}}, nil),
		RecordsByPolicy: recordsFrom("github"),
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
