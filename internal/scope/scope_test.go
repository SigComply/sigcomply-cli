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
		ShouldEvaluate:       true,
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

// A filtered run (--cadence weekly) plans only the policies it selects. A
// declared source that only out-of-filter policies use was neither bound
// nor consulted by this run, and the framework does bind it: the run
// cannot judge it, so it is not missing.
func TestEvaluate_SourceBoundOnlyOutsideTheFilterIsNotMissing(t *testing.T) {
	full := planWith(map[string][]planner.Binding{testSlotUsers: {{SourceID: testSourceOkta}}}, nil)
	got := scope.Evaluate(&scope.Input{
		Declared:        []string{testSourceOkta},
		Configured:      map[string]map[string]any{testSourceOkta: {}},
		Plan:            &planner.RunPlan{},
		FullPlan:        full,
		RecordsByPolicy: recordsFrom(),
	})
	if !got.Complete() || len(got.Missing) != 0 {
		t.Fatalf("Status = %q, Missing = %v; want nothing missing", got.Status, got.Missing)
	}
	if len(got.Sources) != 1 || got.Sources[0].State != scope.SourceNotInRun {
		t.Errorf("Sources = %+v; want %q", got.Sources, scope.SourceNotInRun)
	}
}

// The framework binding nothing to a source is still not_bound, whatever
// the run's filter.
func TestEvaluate_NotBoundJudgedOnTheFullPlan(t *testing.T) {
	full := planWith(map[string][]planner.Binding{testSlotUsers: {{SourceID: testSourceAWSIAM}}}, nil)
	got := scope.Evaluate(&scope.Input{
		Declared:   []string{testSourceOkta},
		Configured: map[string]map[string]any{testSourceOkta: {}},
		Plan:       &planner.RunPlan{},
		FullPlan:   full,
	})
	if len(got.Sources) != 1 || got.Sources[0].State != scope.SourceNotBound {
		t.Errorf("Sources = %+v; want %q", got.Sources, scope.SourceNotBound)
	}
}

// Under --scheduled, a policy that carries forward or a whole-policy
// exception collects nothing; its source returning no records this run is
// not a collection failure.
func TestEvaluate_SourceOnlyUsedByPoliciesThatCollectNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		pp   planner.PlannedPolicy
	}{
		{"carried forward", planner.PlannedPolicy{ShouldEvaluate: false}},
		{"whole-policy exception", planner.PlannedPolicy{ShouldEvaluate: true,
			Exceptions: []*planner.Exception{{State: core.StatusNA, Reason: "r"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pp := tc.pp
			pp.Spec = core.Policy{ID: "p1"}
			pp.Bindings = map[string][]planner.Binding{testSlotUsers: {{SourceID: testSourceOkta}}}
			got := scope.Evaluate(&scope.Input{
				Declared:        []string{testSourceOkta},
				Configured:      map[string]map[string]any{testSourceOkta: {}},
				Plan:            &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
				RecordsByPolicy: recordsFrom(),
			})
			if !got.Complete() {
				t.Fatalf("Missing = %v; want nothing missing", got.Missing)
			}
			if got.Sources[0].State != scope.SourceNotInRun {
				t.Errorf("state = %q; want %q", got.Sources[0].State, scope.SourceNotInRun)
			}
		})
	}
}
