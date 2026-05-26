package evaluator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// makeRule returns a GoRule producing the given canned result.
func makeRule(id string, result core.RuleResult, err error) *GoRule { //nolint:unparam // id is the same in every test today but the param documents intent
	return &GoRule{
		IDValue: id,
		Fn: func(_ context.Context, _ core.RuleInput) (core.RuleResult, error) {
			return result, err
		},
	}
}

func makePlannedPolicy(id, control, ruleRef string, requiredSlots ...string) planner.PlannedPolicy { //nolint:unparam // id is fixed in every test today but the param documents intent
	slots := map[string]core.Slot{}
	for _, s := range requiredSlots {
		slots[s] = core.Slot{Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true}
	}
	return planner.PlannedPolicy{
		Spec: core.Policy{
			ID:           id,
			Control:      control,
			Severity:     core.SeverityHigh,
			RuleRef:      ruleRef,
			Slots:        slots,
			EvidenceMode: core.EvidenceModeAutomated,
		},
		Parameters:     map[string]any{},
		ShouldEvaluate: true,
	}
}

func makePlannedPolicyManual(id, control string) planner.PlannedPolicy { //nolint:unparam // id is fixed in tests but the param documents intent
	return planner.PlannedPolicy{
		Spec: core.Policy{
			ID:           id,
			Control:      control,
			Severity:     core.SeverityMedium,
			EvidenceMode: core.EvidenceModeManual,
			CatalogEntry: "access_review_quarterly",
		},
		Parameters:     map[string]any{},
		ShouldEvaluate: true,
	}
}

func setupRules(t *testing.T, rules ...core.Rule) *registry.Set {
	t.Helper()
	set := registry.NewSet()
	for _, r := range rules {
		if err := set.Rules.Register(r); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	return set
}

func TestEvaluate_NilInputErrors(t *testing.T) {
	_, err := Evaluate(context.Background(), nil)
	if err == nil {
		t.Fatal("want error on nil input")
	}
}

func TestEvaluate_PassThroughRuleResult(t *testing.T) {
	rule := makeRule("rules.r.v1", core.RuleResult{Status: core.StatusPass}, nil)
	set := setupRules(t, rule)
	pp := makePlannedPolicy("p1", "C1", "rules.r.v1", "u")
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: set.Rules,
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p1": {"u": {{ID: "u1"}, {ID: "u2"}}},
		},
		Now: time.Now(),
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(res) != 1 || res[0].Status != core.StatusPass {
		t.Errorf("want pass; got %+v", res)
	}
	if res[0].ResourcesEvaluated != 2 {
		t.Errorf("ResourcesEvaluated = %d; want 2", res[0].ResourcesEvaluated)
	}
}

func TestEvaluate_RuleErrorBecomesErrorStatus(t *testing.T) {
	rule := makeRule("rules.r.v1", core.RuleResult{}, errors.New("kaboom"))
	set := setupRules(t, rule)
	pp := makePlannedPolicy("p1", "C1", "rules.r.v1", "u")
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: set.Rules,
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p1": {"u": {{ID: "u1"}}},
		},
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusError {
		t.Errorf("status = %q; want error", res[0].Status)
	}
}

func TestEvaluate_UnregisteredRule(t *testing.T) {
	set := setupRules(t)
	pp := makePlannedPolicy("p1", "C1", "rules.missing.v1", "u")
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: set.Rules,
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p1": {"u": {{ID: "u1"}}},
		},
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusError {
		t.Errorf("status = %q; want error", res[0].Status)
	}
}

func TestEvaluate_CollectErrorSkipsRule(t *testing.T) {
	rule := makeRule("rules.r.v1", core.RuleResult{Status: core.StatusPass}, nil)
	set := setupRules(t, rule)
	pp := makePlannedPolicy("p1", "C1", "rules.r.v1", "u")
	in := &Input{
		Plan:                  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules:                 set.Rules,
		CollectErrorsByPolicy: map[string]error{"p1": errors.New("AWS unreachable")},
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusError {
		t.Errorf("status = %q; want error", res[0].Status)
	}
	if res[0].Diag["collect_error"] == nil {
		t.Errorf("Diag missing collect_error")
	}
}

func TestEvaluate_RequiredSlotEmptySkips(t *testing.T) {
	rule := makeRule("rules.r.v1", core.RuleResult{Status: core.StatusPass}, nil)
	set := setupRules(t, rule)
	pp := makePlannedPolicy("p1", "C1", "rules.r.v1", "u")
	in := &Input{
		Plan:            &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules:           set.Rules,
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{"p1": {}},
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusSkip {
		t.Errorf("status = %q; want skip", res[0].Status)
	}
}

func TestEvaluate_WholePolicyNAException(t *testing.T) {
	rule := makeRule("rules.r.v1", core.RuleResult{Status: core.StatusFail, Violations: []core.Violation{{ResourceID: "x"}}}, nil)
	set := setupRules(t, rule)
	pp := makePlannedPolicy("p1", "C1", "rules.r.v1", "u")
	pp.Exception = &planner.Exception{State: core.StatusNA, Reason: "not applicable"}
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: set.Rules,
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p1": {"u": {{ID: "u1"}}},
		},
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusNA {
		t.Errorf("status = %q; want na", res[0].Status)
	}
	if len(res[0].Violations) != 0 {
		t.Errorf("expected no violations for NA policy; got %d", len(res[0].Violations))
	}
}

func TestEvaluate_ResourceWaiver(t *testing.T) {
	rule := makeRule("rules.r.v1", core.RuleResult{
		Status: core.StatusFail,
		Violations: []core.Violation{
			{ResourceID: "iam_user_legacy_svc"},
			{ResourceID: "iam_user_alice"},
		},
	}, nil)
	set := setupRules(t, rule)
	pp := makePlannedPolicy("p1", "C1", "rules.r.v1", "u")
	pp.Exception = &planner.Exception{State: core.StatusWaived, ResourceID: "iam_user_legacy_svc"}
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
	if len(res[0].Violations) != 1 {
		t.Errorf("kept violations = %d; want 1", len(res[0].Violations))
	}
	if res[0].Status != core.StatusFail {
		t.Errorf("status = %q; want fail (one survivor)", res[0].Status)
	}
	if res[0].Diag["waived_count"] != 1 {
		t.Errorf("waived_count missing")
	}
}

func TestEvaluate_PatternResourceWaiverSuppressesAll(t *testing.T) {
	rule := makeRule("rules.r.v1", core.RuleResult{
		Status: core.StatusFail,
		Violations: []core.Violation{
			{ResourceID: "legacy_svc_a"},
			{ResourceID: "legacy_svc_b"},
		},
	}, nil)
	set := setupRules(t, rule)
	pp := makePlannedPolicy("p1", "C1", "rules.r.v1", "u")
	pp.Exception = &planner.Exception{State: core.StatusWaived, ResourcePattern: "legacy_*"}
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
	if res[0].Status != core.StatusWaived {
		t.Errorf("status = %q; want waived", res[0].Status)
	}
}

func TestEvaluate_ManualPathA_Pass(t *testing.T) {
	pp := makePlannedPolicyManual("p.manual.1", "C1")
	payload, err := json.Marshal(map[string]any{
		"file_present":       true,
		"in_temporal_window": true,
		"file_valid":         true,
		"expected_uri":       "s3://bucket/manual/access_review_quarterly/2026-Q1/evidence.pdf",
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: nil, // manual Path A doesn't need rules
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p.manual.1": {"_manual": {{ID: "access_review_quarterly/2026-Q1", Payload: payload}}},
		},
		Now: time.Now(),
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusPass {
		t.Errorf("status = %q; want pass", res[0].Status)
	}
}

func TestEvaluate_ManualPathA_MissingFile(t *testing.T) {
	pp := makePlannedPolicyManual("p.manual.1", "C1")
	payload, err := json.Marshal(map[string]any{
		"file_present":       false,
		"in_temporal_window": false,
		"file_valid":         false,
		"expected_uri":       "s3://bucket/manual/access_review_quarterly/2026-Q1/evidence.pdf",
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: nil,
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p.manual.1": {"_manual": {{ID: "access_review_quarterly/2026-Q1", Payload: payload}}},
		},
		Now: time.Now(),
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusFail {
		t.Errorf("status = %q; want fail", res[0].Status)
	}
}

func TestEvaluate_ManualPathA_OutsideWindow(t *testing.T) {
	pp := makePlannedPolicyManual("p.manual.1", "C1")
	payload, err := json.Marshal(map[string]any{
		"file_present":       true,
		"in_temporal_window": false,
		"file_valid":         true,
		"expected_uri":       "s3://bucket/manual/q1/evidence.pdf",
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: nil,
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p.manual.1": {"_manual": {{ID: "q1/evidence", Payload: payload}}},
		},
		Now: time.Now(),
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusFail {
		t.Errorf("status = %q; want fail", res[0].Status)
	}
}

func TestEvaluate_ManualPathA_InvalidPDF(t *testing.T) {
	pp := makePlannedPolicyManual("p.manual.1", "C1")
	payload, err := json.Marshal(map[string]any{
		"file_present":        true,
		"in_temporal_window":  true,
		"file_valid":          false,
		"validation_failures": []string{"missing_pdf_header"},
		"expected_uri":        "s3://bucket/manual/q1/evidence.pdf",
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	in := &Input{
		Plan:  &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Rules: nil,
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			"p.manual.1": {"_manual": {{ID: "q1/evidence", Payload: payload}}},
		},
		Now: time.Now(),
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res[0].Status != core.StatusFail {
		t.Errorf("status = %q; want fail", res[0].Status)
	}
}

func TestRegoRule_InvalidModule(t *testing.T) {
	_, err := NewRegoRule("rules.bad.v1", "this is not valid rego", "data.x.result")
	if err == nil {
		t.Fatal("want error on invalid rego")
	}
}

func TestRegoRule_NoMatchingResultReturnsError(t *testing.T) {
	// Query a key that does not exist in the module.
	module := `package rules.empty.v1
other := 1
`
	rule, err := NewRegoRule("rules.empty.v1", module, "data.rules.empty.v1.result")
	if err != nil {
		t.Fatalf("NewRegoRule: %v", err)
	}
	out, evalErr := rule.Evaluate(context.Background(), core.RuleInput{})
	if evalErr != nil {
		t.Fatalf("Evaluate: %v", evalErr)
	}
	if out.Status != core.StatusError {
		t.Errorf("status = %q; want error", out.Status)
	}
}

func TestRegoRule_NonObjectResult(t *testing.T) {
	module := `package rules.scalar.v1
result := 42
`
	rule, err := NewRegoRule("rules.scalar.v1", module, "data.rules.scalar.v1.result")
	if err != nil {
		t.Fatalf("NewRegoRule: %v", err)
	}
	out, evalErr := rule.Evaluate(context.Background(), core.RuleInput{})
	if evalErr != nil {
		t.Fatalf("Evaluate: %v", evalErr)
	}
	if out.Status != core.StatusError {
		t.Errorf("status = %q; want error", out.Status)
	}
}

func TestGoRule_DelegatesToFn(t *testing.T) {
	called := false
	r := &GoRule{IDValue: "rules.go.v1", Fn: func(_ context.Context, _ core.RuleInput) (core.RuleResult, error) {
		called = true
		return core.RuleResult{Status: core.StatusPass}, nil
	}}
	if r.ID() != "rules.go.v1" {
		t.Errorf("ID = %q", r.ID())
	}
	out, err := r.Evaluate(context.Background(), core.RuleInput{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !called {
		t.Errorf("Fn was not invoked")
	}
	if out.Status != core.StatusPass {
		t.Errorf("status = %q", out.Status)
	}
}
