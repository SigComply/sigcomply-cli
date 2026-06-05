package evaluator

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// ---- evalComparisonOp: in / not_in / unknown ----

func TestPassWhen_Condition_NotIn(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "repos",
		Quantifier: core.QuantifierAll,
		// All repos must NOT be in the disallowed set.
		Condition: &core.PassWhenCondition{Op: "not_in", Field: "payload.visibility", Value: []any{"public"}},
	}}}
	records := map[string][]core.EvidenceRecord{
		"repos": {
			makeRecord("r1", map[string]any{"visibility": "private"}),
			makeRecord("r2", map[string]any{"visibility": "public"}), // in disallowed set → fails not_in
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (r2 is public)", result.Status)
	}
	if len(result.Violations) != 1 || result.Violations[0].ResourceID != "r2" {
		t.Errorf("expected one violation for r2; got %v", result.Violations)
	}
}

// in/not_in where the RHS is not a list: containsValue returns false, so
// `in` never matches (every record violates an `all` of `in`) and
// `not_in` always matches.
func TestPassWhen_InWithNonListRHS_NeverMatches(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "repos",
		Quantifier: core.QuantifierAny,
		Condition:  &core.PassWhenCondition{Op: "in", Field: "payload.visibility", Value: "private"}, // RHS not a list
	}}}
	records := map[string][]core.EvidenceRecord{
		"repos": {makeRecord("r1", map[string]any{"visibility": "private"})},
	}
	result := evaluatePassWhen(spec, records, nil)
	// `in` against a non-list RHS can never be satisfied → any fails.
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (in against non-list is never true)", result.Status)
	}
}

// An unknown comparison operator must surface status=error, not a silent
// pass/fail. This guards the default branch of evalComparisonOp.
func TestPassWhen_UnknownOperator_Errors(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "repos",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "approximately", Field: "payload.x", Value: 1},
	}}}
	records := map[string][]core.EvidenceRecord{
		"repos": {makeRecord("r1", map[string]any{"x": float64(1)})},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusError {
		t.Errorf("status = %q; want error for unknown operator", result.Status)
	}
}

// An unknown quantifier surfaces status=error (guards the default branch
// of evaluatePassWhenClause).
func TestPassWhen_UnknownQuantifier_Errors(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "repos",
		Quantifier: core.PassWhenQuantifier("most"),
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.x", Value: 1},
	}}}
	records := map[string][]core.EvidenceRecord{
		"repos": {makeRecord("r1", map[string]any{"x": float64(1)})},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusError {
		t.Errorf("status = %q; want error for unknown quantifier", result.Status)
	}
}

// ---- evaluateAny: empty record set fails with a slot-less reason ----

func TestPassWhen_Any_EmptyRecordSet_Fails(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:         "detectors",
		Quantifier:   core.QuantifierAny,
		Condition:    &core.PassWhenCondition{Op: "eq", Field: "payload.enabled", Value: true},
		ViolationMsg: "no detector enabled",
	}}}
	result := evaluatePassWhen(spec, map[string][]core.EvidenceRecord{}, nil)
	if result.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail (any over empty set)", result.Status)
	}
	if len(result.Violations) != 1 {
		t.Errorf("violations = %d; want 1", len(result.Violations))
	}
}

// evaluateAny short-circuits its error path: a condition error on the
// first record propagates as status=error.
func TestPassWhen_Any_ConditionError(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "detectors",
		Quantifier: core.QuantifierAny,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.absent", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"detectors": {makeRecord("d1", map[string]any{"present": true})}, // absent field
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusError {
		t.Errorf("status = %q; want error (absent field in any condition)", result.Status)
	}
}

// ---- evaluateCount edge cases ----

// Zero records with min_percentage>0 fails ("no records to evaluate").
func TestPassWhen_Count_ZeroRecords_NonZeroMin_Fails(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:          "keys",
		Quantifier:    core.QuantifierCount,
		MinPercentage: minPct(50),
		Condition:     &core.PassWhenCondition{Op: "eq", Field: "payload.rotated", Value: true},
	}}}
	result := evaluatePassWhen(spec, map[string][]core.EvidenceRecord{}, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (0 records, min 50%%)", result.Status)
	}
}

// Zero records with min_percentage==0 (or nil) passes vacuously.
func TestPassWhen_Count_ZeroRecords_ZeroMin_Passes(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "keys",
		Quantifier: core.QuantifierCount,
		// MinPercentage nil → 0 → vacuous pass.
		Condition: &core.PassWhenCondition{Op: "eq", Field: "payload.rotated", Value: true},
	}}}
	result := evaluatePassWhen(spec, map[string][]core.EvidenceRecord{}, nil)
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (0 records, min 0%%)", result.Status)
	}
}

// A condition error inside count propagates as status=error.
func TestPassWhen_Count_ConditionError(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:          "keys",
		Quantifier:    core.QuantifierCount,
		MinPercentage: minPct(50),
		Condition:     &core.PassWhenCondition{Op: "gte", Field: "payload.age", Value: 1},
	}}}
	records := map[string][]core.EvidenceRecord{
		"keys": {makeRecord("k1", map[string]any{"age": "not-a-number"})},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusError {
		t.Errorf("status = %q; want error (non-numeric in count condition)", result.Status)
	}
}

// ---- evaluateNone: condition error propagates ----

func TestPassWhen_None_ConditionError(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierNone,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.absent", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {makeRecord("u1", map[string]any{"present": true})},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusError {
		t.Errorf("status = %q; want error", result.Status)
	}
}

// evaluateNone dedups by identity_key just like evaluateAll.
func TestPassWhen_None_DedupByIdentityKey(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:        "users",
		Quantifier:  core.QuantifierNone,
		Condition:   &core.PassWhenCondition{Op: "eq", Field: "payload.is_admin", Value: true},
		IdentityKey: "payload.email",
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("u1", map[string]any{"is_admin": true, "email": "a@x.com"}),
			makeRecord("u1b", map[string]any{"is_admin": true, "email": "a@x.com"}), // dup email
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail", result.Status)
	}
	if len(result.Violations) != 1 {
		t.Errorf("violations = %d; want 1 (dedup by email)", len(result.Violations))
	}
}

// ---- getField: top-level id/type/source_id, nested payload, errors ----

func TestPassWhen_TopLevelFields(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value any
		want  core.PolicyStatus
	}{
		{"id matches", "id", "u1", core.StatusPass},
		{"type matches", "type", "directory_user", core.StatusPass},
		{"source_id matches", "source_id", "aws.iam", core.StatusPass},
		{"id mismatch fails", "id", "other", core.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot:       "users",
				Quantifier: core.QuantifierAll,
				Condition:  &core.PassWhenCondition{Op: "eq", Field: c.field, Value: c.value},
			}}}
			records := map[string][]core.EvidenceRecord{
				"users": {makeRecord("u1", map[string]any{})}, // type=directory_user, source=aws.iam
			}
			result := evaluatePassWhen(spec, records, nil)
			if result.Status != c.want {
				t.Errorf("field %q: status = %q; want %q", c.field, result.Status, c.want)
			}
		})
	}
}

// A nested payload dot-path resolves through intermediate objects.
func TestPassWhen_NestedPayloadPath(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "buckets",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.encryption.algorithm", Value: "AES256"},
	}}}
	records := map[string][]core.EvidenceRecord{
		"buckets": {
			makeRecord("b1", map[string]any{"encryption": map[string]any{"algorithm": "AES256"}}),
			makeRecord("b2", map[string]any{"encryption": map[string]any{"algorithm": "none"}}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (b2 not AES256)", result.Status)
	}
}

// A dot-path that descends into a non-object intermediate is treated as
// "absent" → comparison errors.
func TestPassWhen_NestedPathThroughScalar_Errors(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "buckets",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.name.deeper", Value: "x"},
	}}}
	records := map[string][]core.EvidenceRecord{
		"buckets": {makeRecord("b1", map[string]any{"name": "flat-string"})}, // name is scalar, not object
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusError {
		t.Errorf("status = %q; want error (cannot descend into scalar)", result.Status)
	}
}

// A $params reference on the Field (LHS) is not resolved — it falls
// through to not-found and errors.
func TestPassWhen_ParamsOnFieldSide_Errors(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "buckets",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "$params.region", Value: "us-east-1"},
	}}}
	records := map[string][]core.EvidenceRecord{
		"buckets": {makeRecord("b1", map[string]any{"region": "us-east-1"})},
	}
	result := evaluatePassWhen(spec, records, map[string]any{"region": "us-east-1"})
	if result.Status != core.StatusError {
		t.Errorf("status = %q; want error ($params not valid on Field side)", result.Status)
	}
}

// A param reference that names a key not present in params resolves to
// the literal string verbatim (the $params.x token), so the comparison
// uses that literal.
func TestPassWhen_UnresolvedParamRef_FallsThroughToLiteral(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "buckets",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.region", Value: "$params.missing"},
	}}}
	records := map[string][]core.EvidenceRecord{
		"buckets": {makeRecord("b1", map[string]any{"region": "$params.missing"})},
	}
	// With no params map, "$params.missing" stays literal; the record's
	// region equals that literal, so all pass.
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (literal compare)", result.Status)
	}
}

// ---- deepEqual / numeric coercion via behavior ----

// A YAML int value (Go int) compares equal to a JSON float64 payload
// value of the same magnitude.
func TestPassWhen_IntVsFloat_Equal(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "keys",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.count", Value: 3}, // Go int
	}}}
	records := map[string][]core.EvidenceRecord{
		"keys": {makeRecord("k1", map[string]any{"count": float64(3)})}, // JSON float64
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (int 3 == float64 3)", result.Status)
	}
}

// Boolean equality flows through the non-numeric fmt.Sprint fallback.
func TestPassWhen_BoolEquality(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "flags",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "neq", Field: "payload.on", Value: false},
	}}}
	records := map[string][]core.EvidenceRecord{
		"flags": {makeRecord("f1", map[string]any{"on": true})},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (true != false)", result.Status)
	}
}

// A record with an empty payload: any payload.* field is absent, so a
// comparison errors (guards getPayloadField's empty-payload branch).
func TestPassWhen_EmptyPayload_FieldAbsentErrors(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.mfa", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {{ID: "u1", Type: "directory_user"}}, // nil payload
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusError {
		t.Errorf("status = %q; want error (empty payload, field absent)", result.Status)
	}
}

// toFloat64 handles the integer-typed RHS produced when a YAML param is
// an int64; an lt comparison against it must work numerically.
func TestPassWhen_NumericComparison_Int64Param(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "keys",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "lt", Field: "payload.age", Value: "$params.max_age"},
	}}}
	records := map[string][]core.EvidenceRecord{
		"keys": {makeRecord("k1", map[string]any{"age": float64(10)})},
	}
	// int64 RHS exercises the int64 case of toFloat64.
	result := evaluatePassWhen(spec, records, map[string]any{"max_age": int64(90)})
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (10 < 90)", result.Status)
	}
}

// recordIdentity falls back to rec.ID when the identity_key field is
// absent on a record.
func TestPassWhen_IdentityKeyAbsent_FallsBackToID(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:        "users",
		Quantifier:  core.QuantifierAll,
		Condition:   &core.PassWhenCondition{Op: "eq", Field: "payload.ok", Value: true},
		IdentityKey: "payload.email", // absent on the record below
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {makeRecord("u-fallback", map[string]any{"ok": false})}, // no email
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail", result.Status)
	}
	if result.Violations[0].ResourceID != "u-fallback" {
		t.Errorf("ResourceID = %q; want fallback to rec.ID", result.Violations[0].ResourceID)
	}
}

// renderMsg leaves an unresolved {{.payload.missing}} token verbatim.
func TestPassWhen_ViolationMsg_UnresolvedTokenKept(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:         "users",
		Quantifier:   core.QuantifierAll,
		Condition:    &core.PassWhenCondition{Op: "eq", Field: "payload.ok", Value: true},
		ViolationMsg: "user {{.id}} field {{.payload.missing}}",
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {makeRecord("u1", map[string]any{"ok": false})},
	}
	result := evaluatePassWhen(spec, records, nil)
	want := "user u1 field {{.payload.missing}}"
	if result.Violations[0].Reason != want {
		t.Errorf("Reason = %q; want %q (unresolved token kept)", result.Violations[0].Reason, want)
	}
}

// Multiple clauses: a failure in any clause fails the policy, and
// violations from all failing clauses accumulate.
func TestPassWhen_MultipleClauses_ViolationsAccumulate(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{
		{
			Slot:       "users",
			Quantifier: core.QuantifierAll,
			Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.mfa", Value: true},
		},
		{
			Slot:       "buckets",
			Quantifier: core.QuantifierAll,
			Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.encrypted", Value: true},
		},
	}}
	records := map[string][]core.EvidenceRecord{
		"users":   {makeRecord("u1", map[string]any{"mfa": false})},
		"buckets": {makeRecord("b1", map[string]any{"encrypted": false})},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail", result.Status)
	}
	if len(result.Violations) != 2 {
		t.Errorf("violations = %d; want 2 (one per clause)", len(result.Violations))
	}
}

// An error in an early clause short-circuits the whole policy to error,
// even if a later clause would pass.
func TestPassWhen_EarlyClauseError_ShortCircuits(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{
		{
			Slot:       "users",
			Quantifier: core.QuantifierAll,
			Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.absent", Value: true},
		},
		{
			Slot:       "buckets",
			Quantifier: core.QuantifierAll,
			Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.encrypted", Value: true},
		},
	}}
	records := map[string][]core.EvidenceRecord{
		"users":   {makeRecord("u1", map[string]any{"present": true})}, // absent field → error
		"buckets": {makeRecord("b1", map[string]any{"encrypted": true})},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusError {
		t.Errorf("status = %q; want error (clause 1 errors)", result.Status)
	}
}
