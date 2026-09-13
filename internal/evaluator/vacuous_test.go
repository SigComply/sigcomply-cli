package evaluator

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func allClause(filter *core.PassWhenCondition) *core.PassWhenSpec {
	return &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierAll,
		Filter:     filter,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.mfa", Value: true},
	}}}
}

// The live vacuous pass: the slot is populated, so requiredSlotsPopulated
// is satisfied, but the filter matches nothing and `all` passes over the
// empty set. countResources reports the pre-filter population, so without
// the diagnostic this reads as "all N resources passed".
func TestPassWhen_FilteredToEmpty_IsReportedVacuous(t *testing.T) {
	recs := map[string][]core.EvidenceRecord{"users": {
		makeRecord("u1", map[string]any{"mfa": false, "kind": "service"}),
		makeRecord("u2", map[string]any{"mfa": false, "kind": "service"}),
	}}
	spec := allClause(&core.PassWhenCondition{Op: "eq", Field: "payload.kind", Value: "admin"})
	got := evaluatePassWhen(spec, newEvalCtx(recs, nil, nil))

	if got.Status != core.StatusPass {
		t.Fatalf("status = %q; want pass (empty set is still vacuously true)", got.Status)
	}
	v, ok := got.Diag["vacuous_clauses"].([]string)
	if !ok || len(v) != 1 || v[0] != "users" {
		t.Errorf("Diag[vacuous_clauses] = %v; want [users]", got.Diag["vacuous_clauses"])
	}
}

func TestPassWhen_EmptySlot_IsReportedVacuous(t *testing.T) {
	got := evaluatePassWhen(allClause(nil), newEvalCtx(map[string][]core.EvidenceRecord{"users": {}}, nil, nil))
	if got.Status != core.StatusPass {
		t.Fatalf("status = %q; want pass", got.Status)
	}
	if _, ok := got.Diag["vacuous_clauses"]; !ok {
		t.Error("an empty slot must be reported vacuous")
	}
}

// A clause that really examined records must stay clean — otherwise the
// diagnostic is noise on every passing run.
func TestPassWhen_RealEvaluation_NotVacuous(t *testing.T) {
	recs := map[string][]core.EvidenceRecord{"users": {makeRecord("u1", map[string]any{"mfa": true})}}
	got := evaluatePassWhen(allClause(nil), newEvalCtx(recs, nil, nil))
	if got.Status != core.StatusPass {
		t.Fatalf("status = %q; want pass", got.Status)
	}
	if got.Diag != nil {
		t.Errorf("Diag = %v; want nil for a clause that examined records", got.Diag)
	}
}

// `any` already fails on the empty set, so it needs no vacuity report.
func TestPassWhen_AnyQuantifier_NotReportedVacuous(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierAny,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.mfa", Value: true},
	}}}
	got := evaluatePassWhen(spec, newEvalCtx(map[string][]core.EvidenceRecord{"users": {}}, nil, nil))
	if got.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail", got.Status)
	}
}
