package evaluator

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// makeRecord builds an EvidenceRecord with a JSON payload from a map.
func makeRecord(id string, payload map[string]any) core.EvidenceRecord {
	p, err := json.Marshal(payload)
	if err != nil {
		panic("makeRecord: " + err.Error())
	}
	return core.EvidenceRecord{
		ID:          id,
		Type:        "directory_user",
		SourceID:    "aws.iam",
		Payload:     p,
		CollectedAt: time.Now(),
	}
}

func minPct(v float64) *float64 { return &v }

// ---- pass_when quantifier: all ----

func TestPassWhen_All_AllPass(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.mfa_enabled", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("u1", map[string]any{"mfa_enabled": true}),
			makeRecord("u2", map[string]any{"mfa_enabled": true}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass", result.Status)
	}
}

func TestPassWhen_All_SomeFail(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:         "users",
		Quantifier:   core.QuantifierAll,
		Condition:    &core.PassWhenCondition{Op: "eq", Field: "payload.mfa_enabled", Value: true},
		ViolationMsg: "User {{.id}} has no MFA",
		IdentityKey:  "id",
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("u1", map[string]any{"mfa_enabled": true}),
			makeRecord("u2", map[string]any{"mfa_enabled": false}),
			makeRecord("u3", map[string]any{"mfa_enabled": false}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", result.Status)
	}
	if len(result.Violations) != 2 {
		t.Errorf("violations = %d; want 2", len(result.Violations))
	}
	if result.Violations[0].Reason != "User u2 has no MFA" {
		t.Errorf("violation reason = %q", result.Violations[0].Reason)
	}
}

func TestPassWhen_All_EmptyRecords_Pass(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.mfa_enabled", Value: true},
	}}}
	result := evaluatePassWhen(spec, map[string][]core.EvidenceRecord{}, nil)
	// All of zero records satisfy the condition — vacuously true.
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (vacuous all)", result.Status)
	}
}

// ---- pass_when quantifier: none ----

func TestPassWhen_None_AllPass(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierNone,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.is_admin", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("u1", map[string]any{"is_admin": false}),
			makeRecord("u2", map[string]any{"is_admin": false}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass", result.Status)
	}
}

func TestPassWhen_None_SomeFail(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierNone,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.is_admin", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("u1", map[string]any{"is_admin": false}),
			makeRecord("u2", map[string]any{"is_admin": true}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", result.Status)
	}
	if len(result.Violations) != 1 {
		t.Errorf("violations = %d; want 1", len(result.Violations))
	}
}

// ---- pass_when quantifier: any ----

func TestPassWhen_Any_AtLeastOnePass(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "detectors",
		Quantifier: core.QuantifierAny,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.enabled", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"detectors": {
			makeRecord("d1", map[string]any{"enabled": false}),
			makeRecord("d2", map[string]any{"enabled": true}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass", result.Status)
	}
}

func TestPassWhen_Any_NoneFail(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "detectors",
		Quantifier: core.QuantifierAny,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.enabled", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"detectors": {
			makeRecord("d1", map[string]any{"enabled": false}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", result.Status)
	}
}

// ---- pass_when quantifier: count ----

func TestPassWhen_Count_SufficientPercentage(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:          "keys",
		Quantifier:    core.QuantifierCount,
		MinPercentage: minPct(80),
		Condition:     &core.PassWhenCondition{Op: "eq", Field: "payload.rotated", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"keys": {
			makeRecord("k1", map[string]any{"rotated": true}),
			makeRecord("k2", map[string]any{"rotated": true}),
			makeRecord("k3", map[string]any{"rotated": true}),
			makeRecord("k4", map[string]any{"rotated": true}),
			makeRecord("k5", map[string]any{"rotated": false}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (80%% required, 80%% passing)", result.Status)
	}
}

func TestPassWhen_Count_InsufficientPercentage(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:          "keys",
		Quantifier:    core.QuantifierCount,
		MinPercentage: minPct(90),
		Condition:     &core.PassWhenCondition{Op: "eq", Field: "payload.rotated", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"keys": {
			makeRecord("k1", map[string]any{"rotated": true}),
			makeRecord("k2", map[string]any{"rotated": false}),
			makeRecord("k3", map[string]any{"rotated": false}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", result.Status)
	}
}

// ---- pass_when filter ----

func TestPassWhen_Filter_ExcludesServiceAccounts(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierAll,
		Filter:     &core.PassWhenCondition{Op: "neq", Field: "payload.is_service_account", Value: true},
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.mfa_enabled", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("u1", map[string]any{"mfa_enabled": true, "is_service_account": false}),
			makeRecord("u2", map[string]any{"mfa_enabled": false, "is_service_account": true}), // excluded
			makeRecord("u3", map[string]any{"mfa_enabled": true, "is_service_account": false}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	// u2 is filtered out; u1 and u3 both pass — overall pass.
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (service account filtered out)", result.Status)
	}
}

// ---- pass_when conditions ----

func TestPassWhen_Condition_Neq(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "neq", Field: "payload.status", Value: "inactive"},
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("u1", map[string]any{"status": "active"}),
			makeRecord("u2", map[string]any{"status": "inactive"}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (u2 is inactive)", result.Status)
	}
}

func TestPassWhen_Condition_In(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "repos",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "in", Field: "payload.visibility", Value: []any{"private", "internal"}},
	}}}
	records := map[string][]core.EvidenceRecord{
		"repos": {
			makeRecord("r1", map[string]any{"visibility": "private"}),
			makeRecord("r2", map[string]any{"visibility": "public"}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (r2 is public)", result.Status)
	}
}

func TestPassWhen_Condition_IsSet(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "users",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "is_set", Field: "payload.email"},
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("u1", map[string]any{"email": "alice@example.com"}),
			makeRecord("u2", map[string]any{}), // no email field
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (u2 has no email)", result.Status)
	}
}

func TestPassWhen_Condition_AllOf(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "buckets",
		Quantifier: core.QuantifierAll,
		Condition: &core.PassWhenCondition{
			Op: "all_of",
			Conditions: []*core.PassWhenCondition{
				{Op: "eq", Field: "payload.encryption_at_rest_enabled", Value: true},
				{Op: "eq", Field: "payload.public_access_blocked", Value: true},
			},
		},
	}}}
	records := map[string][]core.EvidenceRecord{
		"buckets": {
			makeRecord("b1", map[string]any{"encryption_at_rest_enabled": true, "public_access_blocked": true}),
			makeRecord("b2", map[string]any{"encryption_at_rest_enabled": true, "public_access_blocked": false}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (b2 fails all_of)", result.Status)
	}
}

func TestPassWhen_Condition_AnyOf(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "instances",
		Quantifier: core.QuantifierAll,
		Condition: &core.PassWhenCondition{
			Op: "any_of",
			Conditions: []*core.PassWhenCondition{
				{Op: "eq", Field: "payload.monitoring_enabled", Value: true},
				{Op: "eq", Field: "payload.logging_enabled", Value: true},
			},
		},
	}}}
	records := map[string][]core.EvidenceRecord{
		"instances": {
			makeRecord("i1", map[string]any{"monitoring_enabled": true, "logging_enabled": false}),
			makeRecord("i2", map[string]any{"monitoring_enabled": false, "logging_enabled": false}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (i2 has neither)", result.Status)
	}
}

// ---- pass_when numeric comparisons ----

func TestPassWhen_Condition_Gte(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "keys",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "lt", Field: "payload.age_days", Value: 90},
	}}}
	records := map[string][]core.EvidenceRecord{
		"keys": {
			makeRecord("k1", map[string]any{"age_days": float64(30)}),  // JSON numbers are float64
			makeRecord("k2", map[string]any{"age_days": float64(100)}), // fails
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (k2 age 100 >= 90)", result.Status)
	}
}

// ---- pass_when param references ----

func TestPassWhen_Condition_ParamRef(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "buckets",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.region", Value: "$params.required_region"},
	}}}
	records := map[string][]core.EvidenceRecord{
		"buckets": {
			makeRecord("b1", map[string]any{"region": "us-east-1"}),
			makeRecord("b2", map[string]any{"region": "eu-west-1"}),
		},
	}
	params := map[string]any{"required_region": "us-east-1"}
	result := evaluatePassWhen(spec, records, params)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (b2 is in wrong region)", result.Status)
	}
	if len(result.Violations) != 1 || result.Violations[0].ResourceID != "b2" {
		t.Errorf("expected violation for b2; got %v", result.Violations)
	}
}

// ---- pass_when via Evaluate (full integration) ----

func TestEvaluate_PassWhenPathB(t *testing.T) {
	pct := float64(0)
	_ = pct
	pp := planner.PlannedPolicy{
		Spec: core.Policy{
			ID:           "p1",
			Controls:     []core.ControlRef{{ControlID: "C1"}},
			Severity:     core.SeverityHigh,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				"users": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true},
			},
			PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot:       "users",
				Quantifier: core.QuantifierAll,
				Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.mfa_enabled", Value: true},
			}}},
		},
		Parameters:     map[string]any{},
		ShouldEvaluate: true,
	}
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: nil, // Path B doesn't touch the rule registry
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p1": {"users": {
				makeRecord("u1", map[string]any{"mfa_enabled": true}),
				makeRecord("u2", map[string]any{"mfa_enabled": false}),
			}},
		},
		Now: time.Now(),
	}
	res, err := Evaluate(nil, in) //nolint:staticcheck // context unused in pass_when path
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusFail {
		t.Errorf("status = %q; want fail (u2 has no MFA)", res[0].Status)
	}
	if len(res[0].Violations) != 1 {
		t.Errorf("violations = %d; want 1", len(res[0].Violations))
	}
}

// ---- dedup by identity_key ----

func TestPassWhen_IdentityKey_Dedup(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:        "users",
		Quantifier:  core.QuantifierAll,
		Condition:   &core.PassWhenCondition{Op: "eq", Field: "payload.mfa_enabled", Value: true},
		IdentityKey: "payload.email",
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("u1", map[string]any{"mfa_enabled": false, "email": "alice@example.com"}),
			makeRecord("u1b", map[string]any{"mfa_enabled": false, "email": "alice@example.com"}), // same email → dedup
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", result.Status)
	}
	if len(result.Violations) != 1 {
		t.Errorf("violations = %d; want 1 (dedup by email)", len(result.Violations))
	}
}

// ---- violation message template ----

func TestPassWhen_ViolationMsgTemplate(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:         "users",
		Quantifier:   core.QuantifierAll,
		Condition:    &core.PassWhenCondition{Op: "eq", Field: "payload.mfa_enabled", Value: true},
		ViolationMsg: "User {{.id}} ({{.payload.email}}) has no MFA",
	}}}
	records := map[string][]core.EvidenceRecord{
		"users": {
			makeRecord("alice", map[string]any{"mfa_enabled": false, "email": "alice@example.com"}),
		},
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", result.Status)
	}
	want := "User alice (alice@example.com) has no MFA"
	if len(result.Violations) == 0 || result.Violations[0].Reason != want {
		t.Errorf("violation reason = %q; want %q", result.Violations[0].Reason, want)
	}
}

// ---- absent-field semantics (Inv #2 robustness) ----

// A comparison against a field the record does not carry must surface as
// status=error, not a silent fail. This is the GitHub null-trap fix: a
// policy reading a field no plugin emits should shout, not falsely
// report non-compliance.
func TestPassWhen_AbsentField_Errors(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "repos",
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.secret_scanning_enabled", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"repos": {makeRecord("r1", map[string]any{"name": "r1"})}, // field absent
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusError {
		t.Fatalf("status = %q; want error for absent field", result.Status)
	}
}

// is_set guards an optional field without erroring: all_of short-circuits
// on the is_set=false branch before the comparison is reached.
func TestPassWhen_AbsentField_IsSetGuardDoesNotError(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "repos",
		Quantifier: core.QuantifierAll,
		Condition: &core.PassWhenCondition{Op: "all_of", Conditions: []*core.PassWhenCondition{
			{Op: "is_set", Field: "payload.optional_flag"},
			{Op: "eq", Field: "payload.optional_flag", Value: true},
		}},
	}}}
	records := map[string][]core.EvidenceRecord{
		"repos": {makeRecord("r1", map[string]any{"name": "r1"})}, // optional_flag absent
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail (guarded, not error)", result.Status)
	}
}

// A filter referencing an absent field excludes the record rather than
// erroring; the remaining (empty) set passes an `all` vacuously.
func TestPassWhen_AbsentField_FilterExcludes(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "repos",
		Quantifier: core.QuantifierAll,
		Filter:     &core.PassWhenCondition{Op: "eq", Field: "payload.is_in_scope", Value: true},
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.compliant", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		"repos": {makeRecord("r1", map[string]any{"name": "r1"})}, // is_in_scope absent -> excluded
	}
	result := evaluatePassWhen(spec, records, nil)
	if result.Status != core.StatusPass {
		t.Fatalf("status = %q; want pass (filtered to empty)", result.Status)
	}
}
