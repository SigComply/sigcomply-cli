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
		PolicyGitDefaultBranchProtected,
		PolicyOktaAppsMFA,
	} {
		if _, ok := set.Policies.Lookup(id); !ok {
			t.Errorf("policy %q not registered", id)
		}
	}
	for _, id := range []string{
		ruleIDGitDefaultBranchProtected,
		ruleIDOktaAppsMFA,
	} {
		if _, ok := set.Rules.Lookup(id); !ok {
			t.Errorf("rule %q not registered", id)
		}
	}
}

func TestGitHubBranchProtectionRule_PassWhenAllProtected(t *testing.T) {
	rule := gitDefaultBranchProtectedRule()
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
	rule := gitDefaultBranchProtectedRule()
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
	rule := gitDefaultBranchProtectedRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"repositories": {
				{ID: "broken", Payload: mustMarshal(t, map[string]any{"default_branch_protected": false})},
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

// MFAEnforcedRule with cross-vendor directory_user — exercises the
// is_active skip and the display_name fallback paths that the rule
// gained when the per-source MFA policies collapsed into the canonical
// PolicyMFAUnion. The "across multiple sources" case is covered
// end-to-end by the orchestrator walking-skeleton fixture.
func TestMFAEnforcedRule_SkipsInactiveUsers(t *testing.T) {
	rule := mfaEnforcedRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"user_directory": {
				directoryUserRecord(t, "u1", "alice", true, "alice@x.com", true),
				directoryUserRecord(t, "u2", "deactivated-bob", false, "bob@x.com", false),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass (inactive bob is skipped)", res.Status)
	}
}

func TestMFAEnforcedRule_FailUsesDisplayName(t *testing.T) {
	rule := mfaEnforcedRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"user_directory": {
				directoryUserRecord(t, "u1", "carol-the-engineer", false, "carol@x.com", true),
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
	if got := res.Violations[0].Reason; got == "" || got == "MFA disabled for " {
		t.Errorf("Reason = %q; want display_name in message", got)
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
		"name":                     name,
		"default_branch":           branch,
		"default_branch_protected": protectionOn,
		"required_reviewers_count": reviews,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return core.EvidenceRecord{
		Type:     "git_repository",
		ID:       name,
		Payload:  payload,
		SourceID: "github",
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

func directoryUserRecord(t *testing.T, id, displayName string, mfa bool, identityKey string, active bool) core.EvidenceRecord {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id":           id,
		"display_name": displayName,
		"mfa_enabled":  mfa,
		"is_active":    active,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return core.EvidenceRecord{
		Type:        "directory_user",
		ID:          id,
		IdentityKey: identityKey,
		Payload:     payload,
		SourceID:    "test-directory",
	}
}
