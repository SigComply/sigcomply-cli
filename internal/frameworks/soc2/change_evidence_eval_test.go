package soc2_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// The CC8.1 change-evidence policies are the first that read what happened
// *during* the period rather than current configuration, and three of their
// four pass_when expressions are shapes no shipped policy used before: a
// filtered quantifier over merged changes, and a two-slot matches_in join
// with a `where` on the index. ValidatePassWhen proves those expressions are
// well formed; it does not prove they mean what the control means. A policy
// that validates but evaluates wrongly is the exact failure this repo treats
// as worse than a missing check — a filtered clause that matches nothing
// passes silently — so these assert behavior against synthetic evidence.

func prRecord(t *testing.T, id string, payload map[string]any) core.EvidenceRecord {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return core.EvidenceRecord{Type: "pull_request", ID: id, Payload: body, SourceID: "github", CollectedAt: time.Unix(0, 0).UTC()}
}

func deployRecord(t *testing.T, id string, payload map[string]any) core.EvidenceRecord {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return core.EvidenceRecord{Type: "deployment", ID: id, Payload: body, SourceID: "github", CollectedAt: time.Unix(0, 0).UTC()}
}

// mergedChange builds a fully-populated pull_request payload that passes
// every change-evidence policy, so each test mutates only the field under
// test and an unrelated regression cannot masquerade as the expected failure.
// the author-vs-approver distinction these policies turn on legible.
//
//nolint:unparam // author is fixed in every case today, but naming it keeps
func mergedChange(number int, author string) map[string]any {
	return map[string]any{
		"repository": "acme/api", "number": number, "author": author,
		"merged_by": "carol", "target_branch": "main",
		"merge_commit_sha": "sha-ok", "merged_at": "2026-08-01T10:00:00Z",
		"approval_count": 1, "independent_approval_count": 1,
		"approved_before_merge": true, "checks_passed": true,
	}
}

func policyByID(t *testing.T, id string) core.Policy {
	t.Helper()
	policies := soc2.Policies()
	for i := range policies {
		if policies[i].ID == id {
			return policies[i]
		}
	}
	t.Fatalf("policy %q not found in soc2.Policies()", id)
	return core.Policy{}
}

// evalPolicy runs one shipped policy against the given slot records.
func evalPolicy(t *testing.T, id string, records map[string][]core.EvidenceRecord) core.PolicyResult {
	t.Helper()
	spec := policyByID(t, id)
	in := &evaluator.Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{{
			Spec: spec, Parameters: map[string]any{}, ShouldEvaluate: true,
		}}},
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{id: records},
		Now:             time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC),
	}
	res, err := evaluator.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate(%s): %v", id, err)
	}
	if len(res) != 1 {
		t.Fatalf("Evaluate(%s) returned %d results; want 1", id, len(res))
	}
	return res[0]
}

func TestChangeEvidencePolicies_SingleSlot(t *testing.T) {
	const (
		approved = "soc2.cc8.1.changes_independently_approved"
		checks   = "soc2.cc8.1.changes_passed_checks"
		ordering = "soc2.cc8.1.approval_precedes_merge"
	)
	tests := []struct {
		name       string
		policy     string
		mutate     func(m map[string]any)
		wantStatus core.PolicyStatus
		wantFailed int
	}{
		{"independently approved passes", approved, nil, core.StatusPass, 0},
		{"self-approved only fails", approved, func(m map[string]any) { m["independent_approval_count"] = 0; m["approval_count"] = 1 }, core.StatusFail, 1},
		{"checks passed passes", checks, nil, core.StatusPass, 0},
		{"merged without checks fails", checks, func(m map[string]any) { m["checks_passed"] = false }, core.StatusFail, 1},
		{"approval before merge passes", ordering, nil, core.StatusPass, 0},
		{"retroactive approval fails", ordering, func(m map[string]any) { m["approved_before_merge"] = false }, core.StatusFail, 1},
		// The ordering policy filters to changes carrying an independent
		// approval. An unapproved change must fall OUT of that scope rather
		// than being reported twice — changes_independently_approved owns it.
		{"unapproved change is out of ordering scope", ordering, func(m map[string]any) {
			m["independent_approval_count"] = 0
			m["approved_before_merge"] = false
		}, core.StatusPass, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := mergedChange(1, "alice")
			if tc.mutate != nil {
				tc.mutate(p)
			}
			got := evalPolicy(t, tc.policy, map[string][]core.EvidenceRecord{
				"evidence": {prRecord(t, "acme/api#1", p)},
			})
			if got.Status != tc.wantStatus {
				t.Errorf("status = %q; want %q (violations: %+v)", got.Status, tc.wantStatus, got.Violations)
			}
			if got.ResourcesFailed != tc.wantFailed {
				t.Errorf("ResourcesFailed = %d; want %d", got.ResourcesFailed, tc.wantFailed)
			}
		})
	}
}

// The violation's ResourceID is the string a customer must type into a
// scoped exception to waive one change, so it is part of the contract.
func TestChangeEvidence_ViolationResourceIDIsTheRecordID(t *testing.T) {
	p := mergedChange(42, "alice")
	p["independent_approval_count"] = 0
	got := evalPolicy(t, "soc2.cc8.1.changes_independently_approved", map[string][]core.EvidenceRecord{
		"evidence": {prRecord(t, "acme/api#42", p)},
	})
	if len(got.Violations) != 1 {
		t.Fatalf("violations = %+v; want 1", got.Violations)
	}
	if got.Violations[0].ResourceID != "acme/api#42" {
		t.Errorf("ResourceID = %q; want %q", got.Violations[0].ResourceID, "acme/api#42")
	}
}

func TestDeploymentTraceability(t *testing.T) {
	const id = "soc2.cc8.1.production_deploys_from_approved_changes"

	approvedChange := mergedChange(7, "alice")
	approvedChange["merge_commit_sha"] = "sha-approved"

	unapprovedChange := mergedChange(8, "alice")
	unapprovedChange["merge_commit_sha"] = "sha-unapproved"
	unapprovedChange["independent_approval_count"] = 0

	changes := []core.EvidenceRecord{
		prRecord(t, "acme/api#7", approvedChange),
		prRecord(t, "acme/api#8", unapprovedChange),
	}

	prodDeploy := func(sha string) map[string]any {
		return map[string]any{
			"repository": "acme/api", "deployment_id": "900", "environment": "production",
			"is_production": true, "deployed_by": "carol",
			"deployed_at": "2026-08-02T10:00:00Z", "commit_sha": sha, "status": "success",
		}
	}

	tests := []struct {
		name       string
		deployment map[string]any
		wantStatus core.PolicyStatus
	}{
		{"production deploy of an approved change passes", prodDeploy("sha-approved"), core.StatusPass},
		{"production deploy of an unapproved change fails", prodDeploy("sha-unapproved"), core.StatusFail},
		{"production deploy of an unknown commit fails", prodDeploy("sha-nowhere"), core.StatusFail},
		// An empty join key must fail closed, never match arbitrarily.
		{"production deploy with no commit sha fails closed", prodDeploy(""), core.StatusFail},
		// Non-production deployments are filtered out of scope entirely.
		{"staging deploy of an unapproved change is out of scope", func() map[string]any {
			d := prodDeploy("sha-unapproved")
			d["environment"], d["is_production"] = "staging", false
			return d
		}(), core.StatusPass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evalPolicy(t, id, map[string][]core.EvidenceRecord{
				"deployments": {deployRecord(t, "acme/api/deployments/900", tc.deployment)},
				"changes":     changes,
			})
			if got.Status != tc.wantStatus {
				t.Errorf("status = %q; want %q (violations: %+v)", got.Status, tc.wantStatus, got.Violations)
			}
		})
	}
}

// The lookup slot is a join table, not a population under evaluation:
// counting it would report "2 of 3 resources passed" for one deployment.
func TestDeploymentTraceability_LookupSlotNotCountedAsResources(t *testing.T) {
	change := mergedChange(7, "alice")
	change["merge_commit_sha"] = "sha-approved"
	got := evalPolicy(t, "soc2.cc8.1.production_deploys_from_approved_changes", map[string][]core.EvidenceRecord{
		"deployments": {deployRecord(t, "acme/api/deployments/900", map[string]any{
			"repository": "acme/api", "deployment_id": "900", "environment": "production",
			"is_production": true, "deployed_by": "carol",
			"deployed_at": "2026-08-02T10:00:00Z", "commit_sha": "sha-approved", "status": "success",
		})},
		"changes": {prRecord(t, "acme/api#7", change)},
	})
	if got.ResourcesEvaluated != 1 {
		t.Errorf("ResourcesEvaluated = %d; want 1 (the deployment only)", got.ResourcesEvaluated)
	}
}
