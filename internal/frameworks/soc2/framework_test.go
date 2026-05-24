package soc2

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

func TestFramework_BasicMetadata(t *testing.T) {
	fw := New()
	if fw.ID() != FrameworkID {
		t.Errorf("ID = %q; want %q", fw.ID(), FrameworkID)
	}
	if fw.Version() != FrameworkVersion {
		t.Errorf("Version = %q; want %q", fw.Version(), FrameworkVersion)
	}
	if len(fw.Controls()) < 4 {
		t.Errorf("want at least 4 controls; got %d", len(fw.Controls()))
	}
	if got, want := len(fw.Policies()), 8; got != want {
		t.Errorf("want %d policies; got %d", want, got)
	}
}

func TestRegister_PopulatesAllRegistries(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, ok := set.Frameworks.Lookup(FrameworkID); !ok {
		t.Errorf("framework not registered")
	}
	for _, ref := range New().Policies() {
		if _, ok := set.Policies.Lookup(ref.PolicyID); !ok {
			t.Errorf("policy %q not registered", ref.PolicyID)
		}
	}
	if _, ok := set.Rules.Lookup(ruleIDMFAEnforced); !ok {
		t.Errorf("mfa_enforced rule not registered")
	}
	if _, ok := set.Rules.Lookup(ruleIDManualPresence); !ok {
		t.Errorf("manual_presence rule not registered")
	}
}

func TestRegister_RejectsDuplicate(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := Register(set); err == nil {
		t.Errorf("second Register should fail (duplicate IDs)")
	}
}

func TestManualCatalog_ContainsAccessReview(t *testing.T) {
	cat := ManualCatalog()
	entry, ok := cat["access_review_quarterly"]
	if !ok {
		t.Fatal("access_review_quarterly missing from catalog")
	}
	if entry.Filename != "evidence.pdf" {
		t.Errorf("Filename = %q", entry.Filename)
	}
	if entry.Cadence != "quarterly" {
		t.Errorf("Cadence = %q", entry.Cadence)
	}
}

func TestMFAEnforcedRule_PassWhenAllUsersHaveMFA(t *testing.T) {
	rule := mfaEnforcedRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"user_directory": {
				userRecord(t, "u1", "alice", true, "alice@acme.com"),
				userRecord(t, "u2", "bob", true, "bob@acme.com"),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass", res.Status)
	}
	if len(res.Violations) != 0 {
		t.Errorf("violations = %v; want none", res.Violations)
	}
}

func TestMFAEnforcedRule_FailWhenUserMissingMFA(t *testing.T) {
	rule := mfaEnforcedRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"user_directory": {
				userRecord(t, "u1", "alice", true, "alice@acme.com"),
				userRecord(t, "u2", "bob", false, "bob@acme.com"),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "u2" {
		t.Errorf("violations = %v", res.Violations)
	}
}

func TestMFAEnforcedRule_DedupesByIdentityKey(t *testing.T) {
	rule := mfaEnforcedRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"user_directory": {
				// Alice in AWS — MFA on.
				userRecord(t, "aws-u1", "alice", true, "alice@acme.com"),
				// Alice in Okta — MFA off. Same identity key; first-seen
				// wins, so the duplicate is dropped and the policy passes.
				userRecord(t, "okta-u1", "alice", false, "alice@acme.com"),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass (dedup by identity_key)", res.Status)
	}
}

func TestManualPresenceRule_PassWhenPresentInWindow(t *testing.T) {
	rule := manualPresenceRule()
	payload := mustMarshal(t, map[string]any{"file_present": true, "in_temporal_window": true})
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"review_document": {{ID: "access_review_quarterly/2026-Q1", Payload: payload}},
		},
		Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass", res.Status)
	}
}

func TestManualPresenceRule_FailWhenMissing(t *testing.T) {
	rule := manualPresenceRule()
	payload := mustMarshal(t, map[string]any{"file_present": false})
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"review_document": {{ID: "access_review_quarterly/2026-Q1", Payload: payload}},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 {
		t.Errorf("want 1 violation; got %v", res.Violations)
	}
}

func userRecord(t *testing.T, id, name string, mfa bool, identityKey string) core.EvidenceRecord {
	t.Helper()
	payload := mustMarshal(t, map[string]any{
		"user_name":   name,
		"mfa_enabled": mfa,
	})
	return core.EvidenceRecord{
		Type:        "user_record",
		ID:          id,
		IdentityKey: identityKey,
		Payload:     payload,
		SourceID:    "aws.iam",
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}
