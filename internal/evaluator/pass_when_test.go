package evaluator

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// Slot names, operators, field paths, payload keys and payload values
// shared by the pass_when test files.
const (
	slotUsers     = "users"
	slotRepos     = "repos"
	slotBuckets   = "buckets"
	slotKeys      = "keys"
	slotDetectors = "detectors"
	slotInstances = "instances"

	opNeq   = "neq"
	opAllOf = "all_of"
	opIsSet = "is_set"
	opNotIn = "not_in"

	fieldPayloadMFA        = "payload.mfa"
	fieldPayloadMFAEnabled = "payload.mfa_enabled"
	fieldPayloadIsAdmin    = "payload.is_admin"
	fieldPayloadEnabled    = "payload.enabled"
	fieldPayloadRotated    = "payload.rotated"
	fieldPayloadVisibility = "payload.visibility"
	fieldPayloadEmail      = "payload.email"
	fieldPayloadAbsent     = "payload.absent"
	fieldPayloadCompliant  = "payload.compliant"
	fieldPayloadIsInScope  = "payload.is_in_scope"

	keyMFA              = "mfa"
	keyMFAEnabled       = "mfa_enabled"
	keyIsAdmin          = "is_admin"
	keyIsServiceAccount = "is_service_account"
	keyEnabled          = "enabled"
	keyRotated          = "rotated"
	keyVisibility       = "visibility"
	keyName             = "name"
	keyRegion           = "region"
	keyPresent          = "present"
	keyStatus           = "status"

	testSourceAWSIAM      = "aws.iam"
	testTypeDirectoryUser = "directory_user"
	testEmailAlice        = "alice@example.com"

	regionUSEast1     = "us-east-1"
	statusActive      = "active"
	statusInactive    = "inactive"
	visibilityPrivate = "private"
	visibilityPublic  = "public"
)

// makeRecord builds an EvidenceRecord with a JSON payload from a map.
func makeRecord(id string, payload map[string]any) core.EvidenceRecord {
	p, err := json.Marshal(payload)
	if err != nil {
		panic("makeRecord: " + err.Error())
	}
	return core.EvidenceRecord{
		ID:          id,
		Type:        testTypeDirectoryUser,
		SourceID:    testSourceAWSIAM,
		Payload:     p,
		CollectedAt: time.Now(),
	}
}

func minPct(v float64) *float64 { return &v }

// ---- comparison operator edge cases ----

// gte/lte against a non-numeric field must surface status=error, not
// silently pass (the old compareNumeric collapsed non-numerics to 0,
// so gte/lte returned true for any string field — a false-pass).
func TestPassWhen_GteOnNonNumericField_Errors(t *testing.T) {
	for _, op := range []string{"gte", "lte", "gt", "lt"} {
		spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
			Slot:       slotUsers,
			Quantifier: core.QuantifierAll,
			Condition:  &core.PassWhenCondition{Op: op, Field: "payload.tier", Value: 0},
		}}}
		records := map[string][]core.EvidenceRecord{
			slotUsers: {makeRecord("u1", map[string]any{"tier": "unknown"})},
		}
		result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
		if result.Status != core.StatusError {
			t.Errorf("op %q on non-numeric field: status = %q; want error", op, result.Status)
		}
	}
}

// eq between a string field and a numeric literal must be false: JSON
// types are distinct, so "5" != 5.
func TestPassWhen_EqStringVsNumber_NotEqual(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotUsers,
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.count", Value: 5},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {makeRecord("u1", map[string]any{"count": "5"})},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Errorf("eq(\"5\", 5): status = %q; want fail (string != number)", result.Status)
	}
}

// ---- pass_when quantifier: all ----

func TestPassWhen_All_AllPass(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotUsers,
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadMFAEnabled, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {
			makeRecord("u1", map[string]any{keyMFAEnabled: true}),
			makeRecord("u2", map[string]any{keyMFAEnabled: true}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass", result.Status)
	}
}

func TestPassWhen_All_SomeFail(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:         slotUsers,
		Quantifier:   core.QuantifierAll,
		Condition:    &core.PassWhenCondition{Op: "eq", Field: fieldPayloadMFAEnabled, Value: true},
		ViolationMsg: "User {{.id}} has no MFA",
		IdentityKey:  "id",
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {
			makeRecord("u1", map[string]any{keyMFAEnabled: true}),
			makeRecord("u2", map[string]any{keyMFAEnabled: false}),
			makeRecord("u3", map[string]any{keyMFAEnabled: false}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
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
		Slot:       slotUsers,
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadMFAEnabled, Value: true},
	}}}
	result := evaluatePassWhen(spec, newEvalCtx(map[string][]core.EvidenceRecord{}, nil, nil))
	// All of zero records satisfy the condition — vacuously true.
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (vacuous all)", result.Status)
	}
}

// ---- pass_when quantifier: none ----

func TestPassWhen_None_AllPass(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotUsers,
		Quantifier: core.QuantifierNone,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadIsAdmin, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {
			makeRecord("u1", map[string]any{keyIsAdmin: false}),
			makeRecord("u2", map[string]any{keyIsAdmin: false}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass", result.Status)
	}
}

func TestPassWhen_None_SomeFail(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotUsers,
		Quantifier: core.QuantifierNone,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadIsAdmin, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {
			makeRecord("u1", map[string]any{keyIsAdmin: false}),
			makeRecord("u2", map[string]any{keyIsAdmin: true}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
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
		Slot:       slotDetectors,
		Quantifier: core.QuantifierAny,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadEnabled, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotDetectors: {
			makeRecord("d1", map[string]any{keyEnabled: false}),
			makeRecord("d2", map[string]any{keyEnabled: true}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass", result.Status)
	}
}

func TestPassWhen_Any_NoneFail(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotDetectors,
		Quantifier: core.QuantifierAny,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadEnabled, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotDetectors: {
			makeRecord("d1", map[string]any{keyEnabled: false}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", result.Status)
	}
}

// ---- pass_when quantifier: count ----

func TestPassWhen_Count_SufficientPercentage(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:          slotKeys,
		Quantifier:    core.QuantifierCount,
		MinPercentage: minPct(80),
		Condition:     &core.PassWhenCondition{Op: "eq", Field: fieldPayloadRotated, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotKeys: {
			makeRecord("k1", map[string]any{keyRotated: true}),
			makeRecord("k2", map[string]any{keyRotated: true}),
			makeRecord("k3", map[string]any{keyRotated: true}),
			makeRecord("k4", map[string]any{keyRotated: true}),
			makeRecord("k5", map[string]any{keyRotated: false}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (80%% required, 80%% passing)", result.Status)
	}
}

func TestPassWhen_Count_InsufficientPercentage(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:          slotKeys,
		Quantifier:    core.QuantifierCount,
		MinPercentage: minPct(90),
		Condition:     &core.PassWhenCondition{Op: "eq", Field: fieldPayloadRotated, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotKeys: {
			makeRecord("k1", map[string]any{keyRotated: true}),
			makeRecord("k2", map[string]any{keyRotated: false}),
			makeRecord("k3", map[string]any{keyRotated: false}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", result.Status)
	}
}

// ---- pass_when filter ----

func TestPassWhen_Filter_ExcludesServiceAccounts(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotUsers,
		Quantifier: core.QuantifierAll,
		Filter:     &core.PassWhenCondition{Op: opNeq, Field: "payload.is_service_account", Value: true},
		Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadMFAEnabled, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {
			makeRecord("u1", map[string]any{keyMFAEnabled: true, keyIsServiceAccount: false}),
			makeRecord("u2", map[string]any{keyMFAEnabled: false, keyIsServiceAccount: true}), // excluded
			makeRecord("u3", map[string]any{keyMFAEnabled: true, keyIsServiceAccount: false}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	// u2 is filtered out; u1 and u3 both pass — overall pass.
	if result.Status != core.StatusPass {
		t.Errorf("status = %q; want pass (service account filtered out)", result.Status)
	}
}

// ---- pass_when conditions ----

func TestPassWhen_Condition_Neq(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotUsers,
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: opNeq, Field: "payload.status", Value: statusInactive},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {
			makeRecord("u1", map[string]any{keyStatus: statusActive}),
			makeRecord("u2", map[string]any{keyStatus: statusInactive}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (u2 is inactive)", result.Status)
	}
}

func TestPassWhen_Condition_In(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotRepos,
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "in", Field: fieldPayloadVisibility, Value: []any{visibilityPrivate, "internal"}},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotRepos: {
			makeRecord("r1", map[string]any{keyVisibility: visibilityPrivate}),
			makeRecord("r2", map[string]any{keyVisibility: visibilityPublic}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (r2 is public)", result.Status)
	}
}

func TestPassWhen_Condition_IsSet(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotUsers,
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: opIsSet, Field: fieldPayloadEmail},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {
			makeRecord("u1", map[string]any{linkedByEmail: testEmailAlice}),
			makeRecord("u2", map[string]any{}), // no email field
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (u2 has no email)", result.Status)
	}
}

func TestPassWhen_Condition_AllOf(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotBuckets,
		Quantifier: core.QuantifierAll,
		Condition: &core.PassWhenCondition{
			Op: opAllOf,
			Conditions: []*core.PassWhenCondition{
				{Op: "eq", Field: "payload.encryption_at_rest_enabled", Value: true},
				{Op: "eq", Field: "payload.public_access_blocked", Value: true},
			},
		},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotBuckets: {
			makeRecord("b1", map[string]any{"encryption_at_rest_enabled": true, "public_access_blocked": true}),
			makeRecord("b2", map[string]any{"encryption_at_rest_enabled": true, "public_access_blocked": false}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (b2 fails all_of)", result.Status)
	}
}

func TestPassWhen_Condition_AnyOf(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotInstances,
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
		slotInstances: {
			makeRecord("i1", map[string]any{"monitoring_enabled": true, "logging_enabled": false}),
			makeRecord("i2", map[string]any{"monitoring_enabled": false, "logging_enabled": false}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (i2 has neither)", result.Status)
	}
}

// ---- pass_when numeric comparisons ----

func TestPassWhen_Condition_Gte(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotKeys,
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "lt", Field: "payload.age_days", Value: 90},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotKeys: {
			makeRecord("k1", map[string]any{"age_days": float64(30)}),  // JSON numbers are float64
			makeRecord("k2", map[string]any{"age_days": float64(100)}), // fails
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Errorf("status = %q; want fail (k2 age 100 >= 90)", result.Status)
	}
}

// ---- pass_when param references ----

func TestPassWhen_Condition_ParamRef(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotBuckets,
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.region", Value: "$params.required_region"},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotBuckets: {
			makeRecord("b1", map[string]any{keyRegion: regionUSEast1}),
			makeRecord("b2", map[string]any{keyRegion: "eu-west-1"}),
		},
	}
	params := map[string]any{"required_region": regionUSEast1}
	result := evaluatePassWhen(spec, newEvalCtx(records, params, nil))
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
				slotUsers: {Accepts: []string{testTypeDirectoryUser}, Cardinality: core.SlotOneOrMore, Required: true},
			},
			PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot:       slotUsers,
				Quantifier: core.QuantifierAll,
				Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadMFAEnabled, Value: true},
			}}},
		},
		Parameters:     map[string]any{},
		ShouldEvaluate: true,
	}
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: nil, // Path B doesn't touch the rule registry
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p1": {slotUsers: {
				makeRecord("u1", map[string]any{keyMFAEnabled: true}),
				makeRecord("u2", map[string]any{keyMFAEnabled: false}),
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
		Slot:        slotUsers,
		Quantifier:  core.QuantifierAll,
		Condition:   &core.PassWhenCondition{Op: "eq", Field: fieldPayloadMFAEnabled, Value: true},
		IdentityKey: fieldPayloadEmail,
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {
			makeRecord("u1", map[string]any{keyMFAEnabled: false, linkedByEmail: testEmailAlice}),
			makeRecord("u1b", map[string]any{keyMFAEnabled: false, linkedByEmail: testEmailAlice}), // same email → dedup
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
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
		Slot:         slotUsers,
		Quantifier:   core.QuantifierAll,
		Condition:    &core.PassWhenCondition{Op: "eq", Field: fieldPayloadMFAEnabled, Value: true},
		ViolationMsg: "User {{.id}} ({{.payload.email}}) has no MFA",
	}}}
	records := map[string][]core.EvidenceRecord{
		slotUsers: {
			makeRecord("alice", map[string]any{keyMFAEnabled: false, linkedByEmail: testEmailAlice}),
		},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
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
		Slot:       slotRepos,
		Quantifier: core.QuantifierAll,
		Condition:  &core.PassWhenCondition{Op: "eq", Field: "payload.secret_scanning_enabled", Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotRepos: {makeRecord("r1", map[string]any{keyName: "r1"})}, // field absent
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusError {
		t.Fatalf("status = %q; want error for absent field", result.Status)
	}
}

// is_set guards an optional field without erroring: all_of short-circuits
// on the is_set=false branch before the comparison is reached.
func TestPassWhen_AbsentField_IsSetGuardDoesNotError(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotRepos,
		Quantifier: core.QuantifierAll,
		Condition: &core.PassWhenCondition{Op: opAllOf, Conditions: []*core.PassWhenCondition{
			{Op: opIsSet, Field: "payload.optional_flag"},
			{Op: "eq", Field: "payload.optional_flag", Value: true},
		}},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotRepos: {makeRecord("r1", map[string]any{keyName: "r1"})}, // optional_flag absent
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail (guarded, not error)", result.Status)
	}
}

// A filter referencing an absent field errors the policy rather than
// excluding the record.
//
// This is the vacuous pass that used to be reachable in production: the
// filter could not decide whether the record was in scope, the record
// was dropped anyway, and `all` over the resulting empty set returned
// pass. One unpopulated field turned a real check into a green tick.
// Scope that cannot be decided is an error, so the run stops instead.
func TestPassWhen_AbsentField_FilterErrors(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotRepos,
		Quantifier: core.QuantifierAll,
		Filter:     &core.PassWhenCondition{Op: "eq", Field: fieldPayloadIsInScope, Value: true},
		Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadCompliant, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotRepos: {makeRecord("r1", map[string]any{keyName: "r1"})}, // is_in_scope absent
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusError {
		t.Fatalf("status = %q; want error (filter could not be evaluated)", result.Status)
	}
	reason := fmt.Sprint(result.Diag[diagReason])
	if !strings.Contains(reason, slotRepos) || !strings.Contains(reason, "could not be evaluated") {
		t.Errorf("Diag[reason] = %q; want it to name the slot and the undecidable filter", reason)
	}
	if _, ok := result.Diag["vacuous_clauses"]; ok {
		t.Error("an erroring filter must not also be reported as a vacuous pass")
	}
}

// The is_set guard is what makes tolerating an absent field a decision in
// the policy rather than an accident in the engine: the record is
// excluded, the clause examines nothing, and that is reported as vacuous
// instead of erroring.
func TestPassWhen_AbsentField_IsSetGuardedFilterExcludes(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotRepos,
		Quantifier: core.QuantifierAll,
		Filter: &core.PassWhenCondition{Op: opAllOf, Conditions: []*core.PassWhenCondition{
			{Op: opIsSet, Field: fieldPayloadIsInScope},
			{Op: "eq", Field: fieldPayloadIsInScope, Value: true},
		}},
		Condition: &core.PassWhenCondition{Op: "eq", Field: fieldPayloadCompliant, Value: true},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotRepos: {makeRecord("r1", map[string]any{keyName: "r1"})}, // is_in_scope absent
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusPass {
		t.Fatalf("status = %q; want pass (guarded filter excludes, does not error)", result.Status)
	}
	if _, ok := result.Diag["vacuous_clauses"]; !ok {
		t.Error("a guarded filter that matched nothing must still be reported vacuous")
	}
}

// A record the filter legitimately excludes must not be reported as a
// violation of the condition it was never judged against.
func TestPassWhen_FilterErrorDoesNotLeakViolations(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotRepos,
		Quantifier: core.QuantifierNone,
		Filter:     &core.PassWhenCondition{Op: "eq", Field: "payload.missing", Value: true},
		Condition:  &core.PassWhenCondition{Op: "eq", Field: fieldPayloadCompliant, Value: false},
	}}}
	records := map[string][]core.EvidenceRecord{
		slotRepos: {makeRecord("r1", map[string]any{"compliant": false})},
	}
	result := evaluatePassWhen(spec, newEvalCtx(records, nil, nil))
	if result.Status != core.StatusError {
		t.Fatalf("status = %q; want error", result.Status)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %d; want 0 (nothing was judged)", len(result.Violations))
	}
}
