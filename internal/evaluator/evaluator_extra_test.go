package evaluator

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// ---- manual_check: no record / parse error paths ----

// A manual policy whose synthetic _manual slot has no record surfaces
// status=error (collector failed or source not configured) — never a
// silent pass.
func TestEvaluateManual_NoRecord_Errors(t *testing.T) {
	out := evaluateManual(map[string][]core.EvidenceRecord{})
	if out.Status != core.StatusError {
		t.Errorf("status = %q; want error (no manual record)", out.Status)
	}
}

// A manual record whose payload is not valid JSON surfaces status=error.
func TestEvaluateManual_BadPayload_Errors(t *testing.T) {
	slots := map[string][]core.EvidenceRecord{
		spec.ManualSlotName: {{ID: "x", Payload: json.RawMessage(`{not json`)}},
	}
	out := evaluateManual(slots)
	if out.Status != core.StatusError {
		t.Errorf("status = %q; want error (unparseable payload)", out.Status)
	}
}

// file_present=false with an expected_uri embeds the folder in the
// violation reason so the operator knows exactly where to upload.
func TestEvaluateManual_MissingFile_ReasonNamesURI(t *testing.T) {
	payload := mustJSON(manualPayload{FilePresent: false, ExpectedURI: "s3://b/manual/q1/"})
	slots := map[string][]core.EvidenceRecord{
		spec.ManualSlotName: {{ID: "q1", Payload: payload}},
	}
	out := evaluateManual(slots)
	if out.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail", out.Status)
	}
	if len(out.Violations) != 1 || out.Violations[0].ResourceID != "q1" {
		t.Fatalf("violations = %v; want one for q1", out.Violations)
	}
	if got := out.Violations[0].Reason; got == "" ||
		!containsSubstr(got, "s3://b/manual/q1/") {
		t.Errorf("reason %q should name the expected URI", got)
	}
}

// file_present=false with no expected_uri uses the generic message.
func TestEvaluateManual_MissingFile_NoURI(t *testing.T) {
	payload := mustJSON(manualPayload{FilePresent: false})
	slots := map[string][]core.EvidenceRecord{
		spec.ManualSlotName: {{ID: "q1", Payload: payload}},
	}
	out := evaluateManual(slots)
	if out.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", out.Status)
	}
}

// file_valid=false with validation_failures lists the specific failures.
func TestEvaluateManual_InvalidFile_ListsFailures(t *testing.T) {
	payload := mustJSON(manualPayload{
		FilePresent: true, InTemporalWindow: true, FileValid: false,
		ValidationFails: []string{"unsupported_file_type", "missing_pdf_header"},
	})
	slots := map[string][]core.EvidenceRecord{
		spec.ManualSlotName: {{ID: "q1", Payload: payload}},
	}
	out := evaluateManual(slots)
	if out.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail", out.Status)
	}
	if !containsSubstr(out.Violations[0].Reason, "unsupported_file_type") {
		t.Errorf("reason %q should list validation failures", out.Violations[0].Reason)
	}
}

// file_valid=false with no validation_failures uses the generic message.
func TestEvaluateManual_InvalidFile_NoDetails(t *testing.T) {
	payload := mustJSON(manualPayload{FilePresent: true, InTemporalWindow: true, FileValid: false})
	slots := map[string][]core.EvidenceRecord{
		spec.ManualSlotName: {{ID: "q1", Payload: payload}},
	}
	out := evaluateManual(slots)
	if out.Status != core.StatusFail {
		t.Errorf("status = %q; want fail", out.Status)
	}
}

// ---- evaluateOne dispatch: carry-forward, unknown evidence_mode ----

// A non-evaluated (carry-forward) policy produces a carried_forward
// result that references the prior envelope and never invokes a rule.
func TestEvaluate_CarryForward_ReferencesPriorEnvelope(t *testing.T) {
	priorAt := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	pp := planner.PlannedPolicy{
		Spec:           core.Policy{ID: "p1", EvidenceMode: core.EvidenceModeAutomated},
		ShouldEvaluate: false,
		SkipReason:     "cadence not elapsed",
		PriorState: &core.PolicyState{
			LastRunAt:       priorAt,
			LastEnvelopeRef: "soc2/2026-Q1/run_x/policies/p1/envelopes/e.json",
			LastRunStatus:   core.StatusPass,
		},
	}
	in := &Input{Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	r := res[0]
	if r.Status != core.StatusCarriedForward {
		t.Fatalf("status = %q; want carried_forward", r.Status)
	}
	if r.CarryForward == nil {
		t.Fatal("CarryForward ref is nil")
	}
	if r.CarryForward.LastEnvelopeRef != "soc2/2026-Q1/run_x/policies/p1/envelopes/e.json" {
		t.Errorf("LastEnvelopeRef = %q", r.CarryForward.LastEnvelopeRef)
	}
	if !r.CarryForward.LastEvaluatedAt.Equal(priorAt) {
		t.Errorf("LastEvaluatedAt = %v; want %v", r.CarryForward.LastEvaluatedAt, priorAt)
	}
	if r.Diag["skip_reason"] != "cadence not elapsed" {
		t.Errorf("skip_reason missing: %v", r.Diag)
	}
}

// Carry-forward with nil PriorState still produces a valid (empty) ref —
// covers the buildCarryForwardRef nil-prior branch.
func TestEvaluate_CarryForward_NilPriorState(t *testing.T) {
	pp := planner.PlannedPolicy{
		Spec:           core.Policy{ID: "p1", EvidenceMode: core.EvidenceModeAutomated},
		ShouldEvaluate: false,
		SkipReason:     "skip",
	}
	in := &Input{Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusCarriedForward {
		t.Errorf("status = %q; want carried_forward", res[0].Status)
	}
	if res[0].CarryForward == nil || res[0].CarryForward.LastEnvelopeRef != "" {
		t.Errorf("expected empty-but-non-nil carry-forward ref; got %+v", res[0].CarryForward)
	}
}

// An unrecognized evidence_mode surfaces status=error (the default
// branch of the evaluateOne dispatch — defends against a spec that
// somehow loaded with a bad mode).
func TestEvaluate_UnknownEvidenceMode_Errors(t *testing.T) {
	pp := planner.PlannedPolicy{
		Spec:           core.Policy{ID: "p1", EvidenceMode: core.EvidenceMode("hybrid")},
		ShouldEvaluate: true,
	}
	in := &Input{Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusError {
		t.Errorf("status = %q; want error (unknown evidence_mode)", res[0].Status)
	}
}

// A whole-policy waived exception (no resource scope) short-circuits to
// waived without invoking the rule.
func TestEvaluate_WholePolicyWaivedException(t *testing.T) {
	pp := planner.PlannedPolicy{
		Spec:           core.Policy{ID: "p1", EvidenceMode: core.EvidenceModeAutomated},
		ShouldEvaluate: true,
		Exception:      &planner.Exception{State: core.StatusWaived},
	}
	in := &Input{Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusWaived {
		t.Errorf("status = %q; want waived", res[0].Status)
	}
}

// A manual policy passes end-to-end through Evaluate's manual dispatch
// even when ShouldEvaluate is true and no rule registry is supplied.
func TestEvaluate_ManualDispatch_NoRequiredSlotCheck(t *testing.T) {
	pp := planner.PlannedPolicy{
		Spec: core.Policy{
			ID:           "p.manual",
			EvidenceMode: core.EvidenceModeManual,
			// A required slot is declared but manual dispatch must NOT
			// gate on requiredSlotsPopulated — it handles missing records
			// inside evaluateManual.
			Slots: map[string]core.Slot{
				"_manual": {Accepts: []string{"signed_document"}, Required: true, Cardinality: core.SlotExactlyOne},
			},
		},
		ShouldEvaluate: true,
	}
	payload := mustJSON(manualPayload{FilePresent: true, InTemporalWindow: true, FileValid: true})
	in := &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p.manual": {spec.ManualSlotName: {{ID: "q1", Payload: payload}}},
		},
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusPass {
		t.Errorf("status = %q; want pass", res[0].Status)
	}
}

// ---- countResources: policy-level failure with no per-resource scope ----

// A rule failure whose violations carry no ResourceID counts as exactly
// one logical failure (not zero).
func TestEvaluate_PolicyLevelFailure_CountsAsOne(t *testing.T) {
	rule := makeRule("rules.r.v1", core.RuleResult{
		Status:     core.StatusFail,
		Violations: []core.Violation{{Reason: "policy-wide failure, no resource"}},
	}, nil)
	set := setupRules(t, rule)
	pp := makePlannedPolicy("p1", "C1", "rules.r.v1", "u")
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: set.Rules,
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p1": {"u": {{ID: "u1"}, {ID: "u2"}}},
		},
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].ResourcesEvaluated != 2 {
		t.Errorf("ResourcesEvaluated = %d; want 2", res[0].ResourcesEvaluated)
	}
	if res[0].ResourcesFailed != 1 {
		t.Errorf("ResourcesFailed = %d; want 1 (policy-level failure)", res[0].ResourcesFailed)
	}
}

// ---- rego rule: full input projection + violation projection ----

// A Rego rule that reads input.slots.<name>[_].payload.X and emits a
// status+violations document round-trips through Evaluate. This is the
// only place toRegoInput and projectRegoResult's happy paths are
// exercised.
func TestRegoRule_FullProjection(t *testing.T) {
	module := `package rules.fail.v1
result := {
  "status": "fail",
  "violations": [
    {"resource_id": "u1", "reason": "no mfa", "details": {"k": "v"}},
    "ignored-non-object",
  ],
} if {
  some u in input.slots.users
  u.payload.mfa_enabled == false
}
result := {"status": "pass"} if {
  every u in input.slots.users { u.payload.mfa_enabled == true }
}
`
	rule, err := NewRegoRule("rules.fail.v1", module, "data.rules.fail.v1.result")
	if err != nil {
		t.Fatalf("NewRegoRule: %v", err)
	}
	in := core.RuleInput{
		PolicyID: "p1",
		Now:      time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC),
		Slots: map[string][]core.EvidenceRecord{
			"users": {
				{ID: "u1", SourceID: "aws.iam", Payload: json.RawMessage(`{"mfa_enabled": false}`)},
			},
		},
	}
	out, err := rule.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail", out.Status)
	}
	// One valid violation object; the non-object element is skipped.
	if len(out.Violations) != 1 {
		t.Fatalf("violations = %d; want 1 (non-object skipped)", len(out.Violations))
	}
	v := out.Violations[0]
	if v.ResourceID != "u1" || v.Reason != "no mfa" {
		t.Errorf("violation = %+v", v)
	}
	if v.Details["k"] != "v" {
		t.Errorf("details not projected: %+v", v.Details)
	}
}

// A record with a malformed payload makes toRegoInput fail, surfacing a
// marshal/unmarshal error from Evaluate.
func TestRegoRule_BadPayload_Errors(t *testing.T) {
	module := `package rules.x.v1
result := {"status": "pass"}
`
	rule, err := NewRegoRule("rules.x.v1", module, "data.rules.x.v1.result")
	if err != nil {
		t.Fatalf("NewRegoRule: %v", err)
	}
	in := core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"users": {{ID: "u1", Payload: json.RawMessage(`{not valid`)}},
		},
	}
	if _, evalErr := rule.Evaluate(context.Background(), in); evalErr == nil {
		t.Fatal("expected error from unparseable payload in toRegoInput")
	}
}

// RegoRule.ID returns the registered id.
func TestRegoRule_ID(t *testing.T) {
	rule, err := NewRegoRule("rules.id.v1", "package rules.id.v1\nresult := {\"status\":\"pass\"}\n", "data.rules.id.v1.result")
	if err != nil {
		t.Fatalf("NewRegoRule: %v", err)
	}
	if rule.ID() != "rules.id.v1" {
		t.Errorf("ID = %q", rule.ID())
	}
}

// mustJSON marshals a value for a test fixture, failing on error.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic("mustJSON: " + err.Error())
	}
	return b
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
