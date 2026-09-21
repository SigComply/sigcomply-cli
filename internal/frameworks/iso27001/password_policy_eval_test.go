package iso27001_test

// password_policy_eval_test.go is the ISO twin of the SOC 2 password
// evaluation test. A.8.5 (secure authentication) carries the same two
// reframed questions as CC6.1, built from its own copy of the clause
// builders — a framework package owns its policy library — and two copies
// of a clause are two chances to drift. These cases pin that the ISO
// pair decides a strength_enum source, a platform-fixed source and an
// unanswerable record exactly as the SOC 2 pair does.
//
// This file is an external test package so it can drive the evaluator
// without the framework package importing it.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

const (
	isoPolMinLength  = "iso27001.8.5.password_minimum_length"
	isoPolComplexity = "iso27001.8.5.password_complexity"

	typePasswordPolicyV1 = "password_policy"
	typePasswordPolicyV2 = "password_policy.v2"

	// password_policy payload keys these cases set.
	pwKeyID         = "id"
	pwKeyProvider   = "provider"
	pwKeyScope      = "scope"
	pwKeyMinLength  = "min_length"
	pwKeyMaxAgeDays = "max_age_days"

	providerOkta = "okta"

	scopeDomain       = "domain"
	scopeAccountValue = "account"
)

func isoEvalPolicy(t *testing.T, id string, records []core.EvidenceRecord) core.PolicyResult {
	t.Helper()
	var spec core.Policy
	policies := iso27001.Policies()
	for i := range policies {
		if policies[i].ID == id {
			spec = policies[i]
		}
	}
	if spec.ID == "" {
		t.Fatalf("policy %q not found in iso27001.Policies()", id)
	}
	res, err := evaluator.Evaluate(context.Background(), &evaluator.Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{{
			Spec: spec, Parameters: map[string]any{}, ShouldEvaluate: true,
		}}},
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
			id: {"evidence": records},
		},
		Now: time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Evaluate(%s): %v", id, err)
	}
	if len(res) != 1 {
		t.Fatalf("Evaluate(%s) returned %d results; want 1", id, len(res))
	}
	return res[0]
}

func isoRecord(t *testing.T, typeID, id string, payload map[string]any) core.EvidenceRecord {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return core.EvidenceRecord{
		Type: typeID, ID: id, Payload: body,
		SourceID: providerOkta, CollectedAt: time.Unix(0, 0).UTC(),
	}
}

func TestISOPasswordPolicies_AcrossSchemaVersionsAndModels(t *testing.T) {
	tests := []struct {
		name       string
		policyID   string
		typeID     string
		payload    map[string]any
		wantStatus core.PolicyStatus
		wantVacuum bool
	}{
		{
			name: "v1 per-class record passes complexity", policyID: isoPolComplexity,
			typeID: typePasswordPolicyV1,
			payload: map[string]any{
				pwKeyID: "00pDefault", pwKeyProvider: providerOkta,
				pwKeyMinLength: 12, pwKeyMaxAgeDays: 90, "reuse_prevention_count": 24,
				"requires_uppercase": true, "requires_lowercase": true,
				"requires_numbers": true, "requires_symbols": true,
			},
			wantStatus: core.StatusPass,
		},
		{
			// The reframing: a platform that rates strength rather than
			// counting character classes states a true fact, and A.8.5
			// asks for secure authentication, not for composition rules
			// NIST 800-63B deprecates.
			name: "strength_enum strong passes complexity", policyID: isoPolComplexity,
			typeID: typePasswordPolicyV2,
			payload: map[string]any{
				pwKeyID: "policies/ou-eng", pwKeyProvider: "google_workspace", pwKeyScope: "org_unit",
				pwKeyMinLength: 12, "complexity_model": "strength_enum", "password_strength": "strong",
			},
			wantStatus: core.StatusPass,
		},
		{
			name: "no strength requirement at all fails complexity", policyID: isoPolComplexity,
			typeID: typePasswordPolicyV2,
			payload: map[string]any{
				pwKeyID: "account", pwKeyProvider: "aws", pwKeyScope: scopeAccountValue,
				pwKeyMinLength: 0, "complexity_model": "none",
			},
			wantStatus: core.StatusFail,
		},
		{
			name: "a record stating no complexity answer is out of scope", policyID: isoPolComplexity,
			typeID: typePasswordPolicyV2,
			payload: map[string]any{
				pwKeyID: "example.com", pwKeyProvider: "entra", pwKeyScope: scopeDomain, pwKeyMaxAgeDays: 90,
			},
			wantStatus: core.StatusPass, wantVacuum: true,
		},
		{
			name: "minimum below 12 fails", policyID: isoPolMinLength,
			typeID: typePasswordPolicyV2,
			payload: map[string]any{
				pwKeyID: "00pDefault", pwKeyProvider: providerOkta, pwKeyScope: "group", pwKeyMinLength: 8,
			},
			wantStatus: core.StatusFail,
		},
		{
			name: "an unset minimum is not judged", policyID: isoPolMinLength,
			typeID: typePasswordPolicyV2,
			payload: map[string]any{
				pwKeyID: "example.com", pwKeyProvider: "entra", pwKeyScope: scopeDomain,
				"not_configurable": []any{"min_length"},
			},
			wantStatus: core.StatusPass, wantVacuum: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isoEvalPolicy(t, tc.policyID, []core.EvidenceRecord{
				isoRecord(t, tc.typeID, "p1", tc.payload),
			})
			// status=error is exit 3 for the run and is what an unguarded
			// read of a v2-optional field produces, so it is called out
			// rather than folded into the status comparison.
			if got.Status == core.StatusError {
				t.Fatalf("status = error (%v) — a clause read a field the record does not carry", got.Diag)
			}
			if got.Status != tc.wantStatus {
				t.Errorf("status = %s (%v); want %s", got.Status, got.Violations, tc.wantStatus)
			}
			if vacuous := len(got.VacuousSlots()) > 0; vacuous != tc.wantVacuum {
				t.Errorf("vacuous = %v (%v); want %v", vacuous, got.VacuousSlots(), tc.wantVacuum)
			}
		})
	}
}
