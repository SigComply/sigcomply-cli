package soc2

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

func TestIdentityPolicies_RegisteredAndDistinct(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for _, id := range []string{
		PolicyGitHubBranchProtection,
		PolicyGitHubMembers2FA,
		PolicyOktaUsersMFA,
		PolicyOktaAppsMFA,
	} {
		if _, ok := set.Policies.Lookup(id); !ok {
			t.Errorf("policy %q not registered", id)
		}
	}
	for _, id := range []string{
		ruleIDGitHubBranchProtection,
		ruleIDGitHubMembers2FA,
		ruleIDOktaUsersMFA,
		ruleIDOktaAppsMFA,
	} {
		if _, ok := set.Rules.Lookup(id); !ok {
			t.Errorf("rule %q not registered", id)
		}
	}
}

func TestGitHubBranchProtectionRule_PassWhenAllProtected(t *testing.T) {
	rule := githubBranchProtectionRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"repositories": {
				ghRepoRecord(t, "web", "main", true, 2),
				ghRepoRecord(t, "api", "main", true, 1),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q", res.Status)
	}
}

func TestGitHubBranchProtectionRule_FailWhenAnyUnprotected(t *testing.T) {
	rule := githubBranchProtectionRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"repositories": {
				ghRepoRecord(t, "web", "main", true, 1),
				ghRepoRecord(t, "legacy", "master", false, 0),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "legacy" {
		t.Errorf("violations = %+v", res.Violations)
	}
}

func TestGitHubBranchProtectionRule_EmptyPayloadFallsBackToID(t *testing.T) {
	rule := githubBranchProtectionRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"repositories": {
				{ID: "broken", Payload: mustMarshal(t, map[string]any{"branch_protection_enabled": false})},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q", res.Status)
	}
}

func TestGitHubMembers2FARule_PassWhenAllEnabled(t *testing.T) {
	rule := githubMembers2FARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"members": {
				ghMemberRecord(t, "alice", true, "admin"),
				ghMemberRecord(t, "bob", true, "member"),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q", res.Status)
	}
}

func TestGitHubMembers2FARule_FailWhenAnyDisabled(t *testing.T) {
	rule := githubMembers2FARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"members": {
				ghMemberRecord(t, "alice", true, "admin"),
				ghMemberRecord(t, "bob", false, "member"),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "bob" {
		t.Errorf("violations = %+v", res.Violations)
	}
}

func TestGitHubMembers2FARule_DedupesByIdentity(t *testing.T) {
	rule := githubMembers2FARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"members": {
				// First record wins: 2FA on. Second record (same identity) dropped.
				ghMemberRecord(t, "alice", true, "admin"),
				ghMemberRecord(t, "alice", false, "admin"),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass (dedup)", res.Status)
	}
}

func TestOktaUsersMFARule_PassWhenAllActiveHaveFactor(t *testing.T) {
	rule := oktaUsersMFARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"directory": {
				oktaUserRecord(t, "u1", "alice@x.com", "ACTIVE", 1),
				oktaUserRecord(t, "u2", "bob@x.com", "ACTIVE", 2),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q", res.Status)
	}
}

func TestOktaUsersMFARule_FailWhenActiveUserHasNoFactors(t *testing.T) {
	rule := oktaUsersMFARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"directory": {
				oktaUserRecord(t, "u1", "alice@x.com", "ACTIVE", 0),
				oktaUserRecord(t, "u2", "bob@x.com", "ACTIVE", 2),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "u1" {
		t.Errorf("violations = %+v", res.Violations)
	}
}

func TestOktaUsersMFARule_SkipsNonActiveUsers(t *testing.T) {
	rule := oktaUsersMFARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"directory": {
				oktaUserRecord(t, "u1", "depro@x.com", "DEPROVISIONED", 0),
				oktaUserRecord(t, "u2", "stage@x.com", "STAGED", 0),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass (non-ACTIVE skipped)", res.Status)
	}
}

func TestOktaAppsMFARule_PassWhenAllRequireMFA(t *testing.T) {
	rule := oktaAppsMFARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"applications": {
				oktaAppRecord(t, "0oa1", "Slack", "SAML_2_0", true),
				oktaAppRecord(t, "0oa2", "Salesforce", "OPENID_CONNECT", true),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q", res.Status)
	}
}

func TestOktaAppsMFARule_FailWhenAnyMissingMFA(t *testing.T) {
	rule := oktaAppsMFARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"applications": {
				oktaAppRecord(t, "0oa1", "Slack", "SAML_2_0", true),
				oktaAppRecord(t, "0oa2", "Legacy", "AUTO_LOGIN", false),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "0oa2" {
		t.Errorf("violations = %+v", res.Violations)
	}
}

func TestPayloadInt_VariantsAndEmpty(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		key     string
		want    int
	}{
		{"empty", nil, "x", 0},
		{"missing", []byte(`{}`), "x", 0},
		{"float64", []byte(`{"x":3}`), "x", 3},
		{"non-number", []byte(`{"x":"3"}`), "x", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := payloadInt(c.payload, c.key)
			if err != nil {
				t.Fatalf("payloadInt: %v", err)
			}
			if got != c.want {
				t.Errorf("payloadInt = %d; want %d", got, c.want)
			}
		})
	}
}

func TestPayloadInt_InvalidJSON(t *testing.T) {
	_, err := payloadInt([]byte(`not-json`), "x")
	if err == nil {
		t.Errorf("want JSON parse error")
	}
}

// Test helpers --------------------------------------------------------------

func ghRepoRecord(t *testing.T, name, branch string, protectionOn bool, reviews int) core.EvidenceRecord {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"name":                       name,
		"default_branch":             branch,
		"branch_protection_enabled":  protectionOn,
		"required_reviewers_count":   reviews,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return core.EvidenceRecord{
		Type:     "github_repository",
		ID:       name,
		Payload:  payload,
		SourceID: "github",
	}
}

func ghMemberRecord(t *testing.T, login string, twoFA bool, role string) core.EvidenceRecord {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"login":          login,
		"two_fa_enabled": twoFA,
		"role":           role,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return core.EvidenceRecord{
		Type:        "github_org_member",
		ID:          login,
		IdentityKey: login,
		Payload:     payload,
		SourceID:    "github",
	}
}

func oktaUserRecord(t *testing.T, id, email, status string, factors int) core.EvidenceRecord {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id":               id,
		"email":            email,
		"status":           status,
		"mfa_factor_count": factors,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return core.EvidenceRecord{
		Type:        "okta_user",
		ID:          id,
		IdentityKey: email,
		Payload:     payload,
		SourceID:    "okta",
	}
}

func oktaAppRecord(t *testing.T, id, label, mode string, mfaRequired bool) core.EvidenceRecord {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id":           id,
		"label":        label,
		"sign_on_mode": mode,
		"mfa_required": mfaRequired,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return core.EvidenceRecord{
		Type:     "okta_app",
		ID:       id,
		Payload:  payload,
		SourceID: "okta",
	}
}
