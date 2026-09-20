package aggregator

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

const (
	testFrameworkSOC2        = "soc2"
	testFrameworkISO27001    = "iso27001"
	testFrameworkVersionSOC2 = "soc2-2017@1.0.0"
	testCadenceDaily         = "daily"
	testSlotEvidence         = "evidence"
)

func TestBuild_StampsSchemaAndMetadata(t *testing.T) {
	env := Environment{
		RunID:       "run-1",
		Framework:   testFrameworkSOC2,
		PeriodID:    "2026-Q1",
		CommitSHA:   "deadbeef",
		CommitTime:  time.Date(2026, 2, 15, 13, 55, 0, 0, time.UTC),
		Branch:      "main",
		Repository:  core.Repository{Provider: "github", NameSlug: "acme/infra"},
		CI:          core.CIEnvironment{Provider: "github_actions"},
		CLIVersion:  "1.0.0",
		StartedAt:   time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 2, 15, 14, 1, 42, 0, time.UTC),
	}
	got := Build(nil, &env)
	if got.Schema != SchemaVersion {
		t.Errorf("Schema = %q; want %q", got.Schema, SchemaVersion)
	}
	if got.RunID != "run-1" || got.Framework != testFrameworkSOC2 || got.PeriodID != "2026-Q1" {
		t.Errorf("metadata mismatch: %+v", got)
	}
}

func TestBuild_CountsSummaryAndComplianceScore(t *testing.T) {
	results := []core.PolicyResult{
		{PolicyID: "a", Status: core.StatusPass, ResourcesEvaluated: 5},
		{PolicyID: "b", Status: core.StatusPass, ResourcesEvaluated: 3},
		{PolicyID: "c", Status: core.StatusFail, ResourcesEvaluated: 10, ResourcesFailed: 4},
		{PolicyID: "d", Status: core.StatusSkip},
		{PolicyID: "e", Status: core.StatusError},
		{PolicyID: "f", Status: core.StatusNA},
		{PolicyID: "g", Status: core.StatusWaived},
		{PolicyID: "h", Status: core.StatusCarriedForward},
	}
	got := Build(results, &Environment{})
	s := got.Summary
	if s.PoliciesTotal != 8 || s.PoliciesPassed != 2 || s.PoliciesFailed != 1 ||
		s.PoliciesSkipped != 1 || s.PoliciesError != 1 || s.PoliciesNA != 1 || s.PoliciesWaived != 1 ||
		s.PoliciesCarriedForward != 1 {
		t.Errorf("summary counts mismatch: %+v", s)
	}
	// Every status bucket must sum to the total — guards against a future
	// status being added to the enum but not to buildSummary (the exact
	// gap that hid the carried-forward undercount).
	bucketSum := s.PoliciesPassed + s.PoliciesFailed + s.PoliciesSkipped +
		s.PoliciesError + s.PoliciesNA + s.PoliciesWaived + s.PoliciesCarriedForward
	if bucketSum != s.PoliciesTotal {
		t.Errorf("status buckets sum to %d; want PoliciesTotal=%d", bucketSum, s.PoliciesTotal)
	}
	// denominator = total - skipped - na = 8 - 1 - 1 = 6
	// numerator   = passed + waived + carried_forward = 2 + 1 + 1 = 4
	// score       = 4/6 = 0.666…
	if s.ComplianceScore < 0.66 || s.ComplianceScore > 0.67 {
		t.Errorf("ComplianceScore = %v; want ~0.667", s.ComplianceScore)
	}
}

// TestBuild_CarriedForwardScoresAsPass guards the steady-state case:
// a run dominated by carried-forward (previously-passing) policies must
// not report a depressed compliance score.
func TestBuild_CarriedForwardScoresAsPass(t *testing.T) {
	results := make([]core.PolicyResult, 0, 10)
	for i := 0; i < 8; i++ {
		results = append(results, core.PolicyResult{PolicyID: "cf", Status: core.StatusCarriedForward})
	}
	results = append(results,
		core.PolicyResult{PolicyID: "p1", Status: core.StatusPass},
		core.PolicyResult{PolicyID: "p2", Status: core.StatusPass},
	)
	s := Build(results, &Environment{}).Summary
	// 8 carried + 2 pass, nothing skipped/na => score must be 1.0, not 0.2.
	if s.ComplianceScore < 0.999 {
		t.Errorf("ComplianceScore = %v; want 1.0 (carried-forward counts as pass)", s.ComplianceScore)
	}
}

func TestBuild_MessageRegeneratedFromCounts_NeverFromViolationText(t *testing.T) {
	// A rule could emit "MFA disabled for alice@acme.com" in violation
	// text. The aggregator must not carry that across to the cloud
	// payload — Message is always synthesized from counts.
	results := []core.PolicyResult{
		{
			PolicyID:           "p1",
			Status:             core.StatusFail,
			ResourcesEvaluated: 10,
			ResourcesFailed:    3,
			Violations: []core.Violation{
				{ResourceID: "arn:aws:iam::1:user/alice", Reason: "MFA disabled for alice@acme.com"},
			},
		},
	}
	got := Build(results, &Environment{})
	msg := got.Policies[0].Message
	if !strings.Contains(msg, "3 of 10 resources failed") {
		t.Errorf("Message = %q; want count phrase", msg)
	}
	if strings.Contains(msg, "alice@acme.com") || strings.Contains(msg, "arn:aws:iam") {
		t.Errorf("Message leaked identity: %q", msg)
	}
}

func TestBuild_MessagePerStatus(t *testing.T) {
	cases := []struct {
		status core.PolicyStatus
		want   string
		failed int
		eval   int
	}{
		{core.StatusPass, "passed", 0, 5},
		{core.StatusFail, "failed", 3, 5},
		{core.StatusSkip, "No matching", 0, 0},
		{core.StatusError, "Evaluation error", 0, 0},
		{core.StatusNA, "Not applicable", 0, 0},
		{core.StatusWaived, "Waived by exception", 1, 5},
		{core.StatusCarriedForward, "Carried forward", 0, 5},
	}
	for _, c := range cases {
		got := generateMessage(&core.PolicyResult{
			Status: c.status, ResourcesEvaluated: c.eval, ResourcesFailed: c.failed,
		})
		if !strings.Contains(got, c.want) {
			t.Errorf("status %q message = %q; want substring %q", c.status, got, c.want)
		}
	}
	// Unknown status returns empty string (not an identity leak).
	if got := generateMessage(&core.PolicyResult{Status: "unknown"}); got != "" {
		t.Errorf("unknown status: got %q; want empty", got)
	}
}

func TestBuild_NoFreeformFieldsInJSONOutput(t *testing.T) {
	// Sanity: the payload JSON-marshals cleanly and contains no
	// "violations" key at the top level or inside policies.
	results := []core.PolicyResult{
		{PolicyID: "p1", Status: core.StatusFail, ResourcesEvaluated: 1, ResourcesFailed: 1,
			Violations: []core.Violation{{ResourceID: "x", Reason: "y"}}},
	}
	payload := Build(results, &Environment{Framework: testFrameworkSOC2})
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "violations") {
		t.Errorf("submission payload JSON contains 'violations' key: %s", b)
	}
	if strings.Contains(string(b), "details") {
		t.Errorf("submission payload JSON contains 'details' key: %s", b)
	}
}

func TestBuild_ZeroResultsProducesEmptyPolicies(t *testing.T) {
	got := Build(nil, &Environment{})
	if len(got.Policies) != 0 {
		t.Errorf("Policies = %v; want empty", got.Policies)
	}
	if got.Summary.PoliciesTotal != 0 {
		t.Errorf("PoliciesTotal = %d; want 0", got.Summary.PoliciesTotal)
	}
	if got.Summary.ComplianceScore != 0 {
		t.Errorf("ComplianceScore = %v; want 0 (no denominator)", got.Summary.ComplianceScore)
	}
}

func TestBuild_AggregatedPolicyOmitsRuleVersionWhenEmpty(t *testing.T) {
	results := []core.PolicyResult{{PolicyID: "p1", Status: core.StatusPass}}
	payload := Build(results, &Environment{})
	b, err := json.Marshal(payload.Policies[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "rule_version") {
		t.Errorf("rule_version emitted when empty: %s", b)
	}
}

// A vacuous pass — one whose clauses filtered every record away — has to
// read differently on the wire from a thorough one. `all`/`none` are true
// of the empty set, so both would otherwise arrive at the dashboard as
// "All 500 resources passed."
func TestBuild_VacuousPassIsDistinguishableFromAThoroughOne(t *testing.T) {
	thorough := generateMessage(&core.PolicyResult{
		Status: core.StatusPass, ResourcesEvaluated: 500,
	})
	if !strings.Contains(thorough, "All 500 resources passed") {
		t.Errorf("thorough pass message = %q; want the count sentence", thorough)
	}

	vacuous := generateMessage(&core.PolicyResult{
		Status:             core.StatusPass,
		ResourcesEvaluated: 500,
		Diag:               map[string]any{core.DiagVacuousClauses: []string{testSlotEvidence}},
	})
	if vacuous == thorough {
		t.Fatalf("vacuous pass message is identical to a thorough one: %q", vacuous)
	}
	if !strings.Contains(vacuous, "no resources matched") {
		t.Errorf("vacuous pass message = %q; want it to say nothing matched", vacuous)
	}
	if !strings.Contains(vacuous, "in scope") {
		t.Errorf("vacuous pass message = %q; want the in-scope prompt", vacuous)
	}
	// Slot names are the CLI's vocabulary and stay there: only the
	// generated sentence crosses the aggregation boundary.
	if strings.Contains(vacuous, testSlotEvidence) {
		t.Errorf("vacuous pass message leaked a slot name: %q", vacuous)
	}
	// Rails validates message length at 500 characters.
	if len(vacuous) > 500 {
		t.Errorf("message is %d chars; Rails caps it at 500", len(vacuous))
	}
}

// Read back out of the vault, Diag decodes as map[string]any with []any
// values. The wire message must not silently revert to the thorough
// sentence for a replayed result.
func TestBuild_VacuousPassSurvivesTheVaultJSONShape(t *testing.T) {
	got := generateMessage(&core.PolicyResult{
		Status:             core.StatusPass,
		ResourcesEvaluated: 500,
		Diag:               map[string]any{core.DiagVacuousClauses: []any{testSlotEvidence}},
	})
	if !strings.Contains(got, "no resources matched") {
		t.Errorf("message = %q; want the vacuous sentence for a []any diag", got)
	}
}

// Only a pass is ambiguous. A fail already names counts that cannot be
// mistaken for thoroughness.
func TestBuild_VacuityOnlyChangesThePassSentence(t *testing.T) {
	diag := map[string]any{core.DiagVacuousClauses: []string{testSlotEvidence}}
	for _, status := range []core.PolicyStatus{
		core.StatusFail, core.StatusSkip, core.StatusError,
		core.StatusNA, core.StatusWaived, core.StatusCarriedForward,
	} {
		withDiag := generateMessage(&core.PolicyResult{
			Status: status, ResourcesEvaluated: 5, ResourcesFailed: 1, Diag: diag,
		})
		without := generateMessage(&core.PolicyResult{
			Status: status, ResourcesEvaluated: 5, ResourcesFailed: 1,
		})
		if withDiag != without {
			t.Errorf("status %q: diag changed the message (%q vs %q)", status, withDiag, without)
		}
	}
}

// The v5 half of the same signal. The message says it in prose; the bool
// says it in a form a dashboard can filter, count and trend.
func TestBuild_VacuousPassIsCarriedAsABool(t *testing.T) {
	payload := Build([]core.PolicyResult{
		{
			PolicyID: "p-vacuous", Status: core.StatusPass, ResourcesEvaluated: 500,
			Diag: map[string]any{core.DiagVacuousClauses: []string{testSlotEvidence}},
		},
		{PolicyID: "p-thorough", Status: core.StatusPass, ResourcesEvaluated: 500},
	}, nil)

	byID := map[string]core.AggregatedPolicy{}
	for _, p := range payload.Policies {
		byID[p.PolicyID] = p
	}
	if !byID["p-vacuous"].Vacuous {
		t.Error("a pass that examined nothing must report vacuous")
	}
	if byID["p-thorough"].Vacuous {
		t.Error("a pass that examined 500 resources must not report vacuous")
	}
	// The bool and the sentence are derived once, so they cannot disagree
	// about the same run.
	if strings.Contains(byID["p-vacuous"].Message, "All 500") {
		t.Errorf("message and bool disagree: %q", byID["p-vacuous"].Message)
	}
}

// Replayed out of the vault, Diag decodes with []any values. The bool
// must not silently revert to false.
func TestBuild_VacuousBoolSurvivesTheVaultJSONShape(t *testing.T) {
	payload := Build([]core.PolicyResult{{
		PolicyID: "p1", Status: core.StatusPass, ResourcesEvaluated: 500,
		Diag: map[string]any{core.DiagVacuousClauses: []any{testSlotEvidence}},
	}}, nil)

	if !payload.Policies[0].Vacuous {
		t.Error("vacuous bool lost for a []any diag shape")
	}
}

// VacuousSlots is status-blind: a failing policy can carry the diagnostic
// for one clause while failing on another. Reporting that as a vacuous
// pass would be false twice over - it did not pass, and it did examine
// something.
func TestBuild_VacuousIsNeverTrueForANonPass(t *testing.T) {
	diag := map[string]any{core.DiagVacuousClauses: []string{testSlotEvidence}}
	for _, status := range []core.PolicyStatus{
		core.StatusFail, core.StatusSkip, core.StatusError,
		core.StatusNA, core.StatusWaived, core.StatusCarriedForward,
	} {
		payload := Build([]core.PolicyResult{{
			PolicyID: "p1", Status: status, ResourcesEvaluated: 5, ResourcesFailed: 1, Diag: diag,
		}}, nil)
		if payload.Policies[0].Vacuous {
			t.Errorf("status %q reported vacuous", status)
		}
	}
}

// omitempty: an ordinary pass must not gain a key on the wire.
func TestBuild_VacuousOmittedWhenFalse(t *testing.T) {
	payload := Build([]core.PolicyResult{
		{PolicyID: "p1", Status: core.StatusPass, ResourcesEvaluated: 5},
	}, nil)
	raw, err := json.Marshal(payload.Policies[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "vacuous") {
		t.Errorf("non-vacuous policy carries the key: %s", raw)
	}
}
