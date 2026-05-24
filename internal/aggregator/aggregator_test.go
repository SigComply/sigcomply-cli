package aggregator

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func TestBuild_StampsSchemaAndMetadata(t *testing.T) {
	env := Environment{
		RunID:       "run-1",
		Framework:   "soc2",
		PeriodID:    "2026-Q1",
		CommitSHA:   "deadbeef",
		CommitTime:  time.Date(2026, 2, 15, 13, 55, 0, 0, time.UTC),
		Branch:      "main",
		Repository:  core.Repository{Provider: "github", NameSlug: "acme/infra"},
		CI:          core.CIEnvironment{Provider: "github"},
		CLIVersion:  "1.0.0",
		StartedAt:   time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 2, 15, 14, 1, 42, 0, time.UTC),
	}
	got := Build(nil, &env)
	if got.Schema != SchemaVersion {
		t.Errorf("Schema = %q; want %q", got.Schema, SchemaVersion)
	}
	if got.RunID != "run-1" || got.Framework != "soc2" || got.PeriodID != "2026-Q1" {
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
	}
	got := Build(results, &Environment{})
	s := got.Summary
	if s.PoliciesTotal != 7 || s.PoliciesPassed != 2 || s.PoliciesFailed != 1 ||
		s.PoliciesSkipped != 1 || s.PoliciesError != 1 || s.PoliciesNA != 1 || s.PoliciesWaived != 1 {
		t.Errorf("summary counts mismatch: %+v", s)
	}
	// denominator = total - skipped - na = 7 - 1 - 1 = 5
	// numerator   = passed + waived = 2 + 1 = 3
	// score       = 3/5 = 0.6
	if s.ComplianceScore < 0.59 || s.ComplianceScore > 0.61 {
		t.Errorf("ComplianceScore = %v; want ~0.6", s.ComplianceScore)
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
	payload := Build(results, &Environment{Framework: "soc2"})
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
