package aggregator

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// updateGolden regenerates the committed golden wire payload. Run:
//
//	go test ./internal/aggregator/ -run TestCloudV3_GoldenWireContract -update
//
// then copy the regenerated file into the Rails repo (see the drift
// guard below for the exact destination) so both sides of the
// POST /api/v1/runs contract are exercised against identical bytes.
var updateGolden = flag.Bool("update", false, "regenerate the golden wire payload")

const goldenPath = "testdata/cloud_v3_golden.json"

// railsFixtureRelPath is the sibling Rails repo's vendored copy of the
// same golden bytes, relative to this package directory. When present
// (local dev with both repos checked out) the test asserts the two are
// byte-identical, catching cross-repo drift the moment it happens. It is
// silently skipped in CI where only one repo is checked out.
const railsFixtureRelPath = "../../../sigcomply/spec/fixtures/files/contract/cloud_v3_golden.json"

// goldenPayload builds the canonical SubmissionPayload through the real
// aggregator.Build path — so the golden is literally what the CLI sends
// over the wire, not a hand-maintained mirror that could drift from the
// aggregator's projection. It deliberately exercises every contract
// surface Rails must accept:
//   - all seven PolicyStatus values (pass/fail/skip/error/na/waived/
//     carried_forward) and the matching RunSummary counts + score
//   - v3 multi-framework controls[] with every ControlRelationship
//   - the cadence scalars (configured_cadence, last_evaluated_at,
//     next_due_at, is_carried_forward, policy_content_hash)
//   - a zero NextDueAt that must be OMITTED (not "0001-01-01...")
//   - carry-forward LastEvaluatedAt sourced from the prior ref
func goldenPayload() core.SubmissionPayload {
	commitTime := time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC)
	startedAt := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	completedAt := time.Date(2026, 6, 22, 10, 1, 30, 0, time.UTC)
	nextDue := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	priorEval := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)

	env := &Environment{
		RunID:      "20260622T100000Z-abc123",
		Framework:  "soc2",
		PeriodID:   "2026-Q2",
		CommitSHA:  "deadbeef0000000000000000000000000000beef",
		CommitTime: commitTime,
		Branch:     "main",
		Repository: core.Repository{
			Provider: "github",
			NameSlug: "acme-corp/infrastructure",
			URL:      "https://github.com/acme-corp/infrastructure",
		},
		CI: core.CIEnvironment{
			Provider:    "github_actions",
			Workflow:    "compliance",
			RunURL:      "https://github.com/acme-corp/infrastructure/actions/runs/123",
			WorkerImage: "ubuntu-22.04",
		},
		CLIVersion:  "1.5.0",
		StartedAt:   startedAt,
		CompletedAt: completedAt,
	}

	results := []core.PolicyResult{
		{
			PolicyID: "shared.mfa_enforced",
			Status:   core.StatusPass,
			Severity: core.SeverityHigh,
			Category: "access_control",
			Controls: []core.ControlRef{
				{Framework: "soc2", FrameworkVersion: "soc2-2017@1.0.0", ControlID: "CC6.1", Relationship: core.RelationshipEqual},
				{Framework: "iso27001", FrameworkVersion: "iso27001-2022@1.0.0", ControlID: "A.8.5", Relationship: core.RelationshipSubsetOf},
			},
			ResourcesEvaluated: 42,
			ResourcesFailed:    0,
			RuleVersion:        "1",
			ConfiguredCadence:  "daily",
			NextDueAt:          nextDue,
			PolicyContentHash:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		{
			PolicyID:           "soc2.cc7.2.audit_logging",
			Status:             core.StatusFail,
			Severity:           core.SeverityCritical,
			Category:           "logging",
			Controls:           []core.ControlRef{{Framework: "soc2", FrameworkVersion: "soc2-2017@1.0.0", ControlID: "CC7.2", Relationship: core.RelationshipEqual}},
			ResourcesEvaluated: 10,
			ResourcesFailed:    3,
			RuleVersion:        "2",
			ConfiguredCadence:  "daily",
		},
		{
			PolicyID:          "soc2.cc6.6.firewall_rules",
			Status:            core.StatusSkip,
			Severity:          core.SeverityMedium,
			Category:          "network",
			Controls:          []core.ControlRef{{Framework: "soc2", ControlID: "CC6.6"}},
			ConfiguredCadence: "weekly",
		},
		{
			PolicyID:          "soc2.cc8.1.change_management",
			Status:            core.StatusError,
			Severity:          core.SeverityHigh,
			Category:          "change_management",
			Controls:          []core.ControlRef{{Framework: "soc2", ControlID: "CC8.1"}},
			ConfiguredCadence: "daily",
		},
		{
			PolicyID: "iso27001.a8.physical_media",
			Status:   core.StatusNA,
			Severity: core.SeverityLow,
			Category: "physical_security",
			Controls: []core.ControlRef{
				{Framework: "iso27001", FrameworkVersion: "iso27001-2022@1.0.0", ControlID: "A.7.10", Relationship: core.RelationshipIntersects},
			},
		},
		{
			PolicyID:           "soc2.cc1.4.background_checks",
			Status:             core.StatusWaived,
			Severity:           core.SeverityMedium,
			Category:           "hr",
			Controls:           []core.ControlRef{{Framework: "soc2", ControlID: "CC1.4", Relationship: core.RelationshipSupersetOf}},
			ResourcesEvaluated: 5,
			ResourcesFailed:    1,
		},
		{
			PolicyID:          "soc2.cc6.1.password_policy",
			Status:            core.StatusCarriedForward,
			Severity:          core.SeverityHigh,
			Category:          "access_control",
			Controls:          []core.ControlRef{{Framework: "soc2", ControlID: "CC6.1"}},
			ConfiguredCadence: "quarterly",
			PolicyContentHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			// NextDueAt intentionally zero — must be omitted from the wire.
			CarryForward: &core.CarryForwardRef{
				LastEvaluatedAt: priorEval,
				LastEnvelopeRef: "soc2/2026-Q2/run_prior/policies/soc2.cc6.1.password_policy/envelopes/e.json",
				LastKnownStatus: core.StatusPass,
			},
		},
	}

	return Build(results, env)
}

// TestCloudV3_GoldenWireContract locks the exact JSON bytes the CLI
// sends to Rails POST /api/v1/runs. The Rails repo POSTs a byte-
// identical fixture (spec/requests/api/v1/runs_contract_golden_spec.rb)
// and asserts it persists, so this golden is the single source of truth
// for the cross-repo wire contract. A change here that is not mirrored
// in Rails (or vice-versa) breaks one side's tests.
func TestCloudV3_GoldenWireContract(t *testing.T) {
	payload := goldenPayload()

	got, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	got = append(got, '\n')

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(goldenPath, got, 0o600); err != nil {
			t.Fatalf("WriteFile golden: %v", err)
		}
		t.Logf("wrote %s", goldenPath)
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden wire payload drifted.\nRun: go test ./internal/aggregator/ -run %s -update\nand mirror the file into the Rails fixture.\n\n--- got ---\n%s", t.Name(), got)
	}

	// Cross-repo drift guard: when the sibling Rails repo is checked
	// out, its vendored fixture must be byte-identical. Skipped (not
	// failed) when the Rails repo is absent, e.g. in the CLI's own CI.
	if railsBytes, err := os.ReadFile(railsFixtureRelPath); err == nil {
		if !bytes.Equal(railsBytes, want) {
			t.Errorf("Rails fixture %s has drifted from the CLI golden.\nCopy %s over it.", railsFixtureRelPath, goldenPath)
		}
	}
}

// TestCloudV3_Golden_NoIdentityKeys is a defense-in-depth scan over the
// actual golden bytes: no key or value that the privacy boundary forbids
// may appear in the serialized contract sample. Complements the
// structural reflection test in core/cloud_test.go by checking real
// emitted JSON, not just the type graph.
func TestCloudV3_Golden_NoIdentityKeys(t *testing.T) {
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(want, &generic); err != nil {
		t.Fatalf("golden is not valid JSON: %v", err)
	}
	forbidden := []string{"violations", "violation", "resources", "identifiers",
		"arn", "email", "username", "account_id", "user_id", "file_hash", "raw"}
	assertNoForbiddenKeys(t, generic, forbidden, "")
}

func assertNoForbiddenKeys(t *testing.T, v any, forbidden []string, path string) {
	t.Helper()
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			for _, bad := range forbidden {
				if k == bad {
					t.Errorf("forbidden key %q at %s", k, path)
				}
			}
			assertNoForbiddenKeys(t, child, forbidden, path+"."+k)
		}
	case []any:
		for i, child := range node {
			assertNoForbiddenKeys(t, child, forbidden, path)
			_ = i
		}
	}
}
