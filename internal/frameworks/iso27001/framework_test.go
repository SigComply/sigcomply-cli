package iso27001

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
	if len(fw.Controls()) < 5 {
		t.Errorf("want at least 5 controls; got %d", len(fw.Controls()))
	}
	if len(fw.Policies()) != 4 {
		t.Errorf("want 4 policies (cloudtrail_logging is deferred); got %d", len(fw.Policies()))
	}
}

func TestControls_CoverRepresentativeAnnexA(t *testing.T) {
	want := []string{
		"ISO27001.A.5.15",
		"ISO27001.A.5.18",
		"ISO27001.A.8.2",
		"ISO27001.A.8.5",
		"ISO27001.A.8.7",
		"ISO27001.A.8.16",
		"ISO27001.A.8.24",
	}
	have := make(map[string]struct{})
	for _, c := range Controls() {
		have[c.ID] = struct{}{}
	}
	for _, id := range want {
		if _, ok := have[id]; !ok {
			t.Errorf("control %q missing from catalog", id)
		}
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
	for _, id := range []string{ruleIDMFAEnforced, ruleIDManualPresence, ruleIDPrivilegedMFA, ruleIDEvidenceSigned} {
		if _, ok := set.Rules.Lookup(id); !ok {
			t.Errorf("rule %q not registered", id)
		}
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
	entry, ok := cat["iso27001_access_review"]
	if !ok {
		t.Fatal("iso27001_access_review missing from catalog")
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
				userRecord(t, "u1", "alice", true, false, "alice@acme.com"),
				userRecord(t, "u2", "bob", true, false, "bob@acme.com"),
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
				userRecord(t, "u1", "alice", true, false, "alice@acme.com"),
				userRecord(t, "u2", "bob", false, false, "bob@acme.com"),
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
				userRecord(t, "aws-u1", "alice", true, false, "alice@acme.com"),
				// Same identity key, MFA off — should be deduped out.
				userRecord(t, "okta-u1", "alice", false, false, "alice@acme.com"),
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

func TestPrivilegedMFARule_PassWhenAdminHasMFA(t *testing.T) {
	rule := privilegedMFARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"user_directory": {
				userRecord(t, "u1", "alice", true, true, "alice@acme.com"), // admin with MFA — ok
				userRecord(t, "u2", "bob", false, false, "bob@acme.com"),   // non-admin no MFA — ignored
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

func TestPrivilegedMFARule_FailWhenAdminMissingMFA(t *testing.T) {
	rule := privilegedMFARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"user_directory": {
				userRecord(t, "u1", "alice", false, true, "alice@acme.com"), // admin without MFA — VIOLATION
				userRecord(t, "u2", "bob", true, true, "bob@acme.com"),      // admin with MFA — ok
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "u1" {
		t.Errorf("violations = %v", res.Violations)
	}
}

func TestPrivilegedMFARule_IgnoresNonAdmins(t *testing.T) {
	rule := privilegedMFARule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"user_directory": {
				userRecord(t, "u1", "alice", false, false, "alice@acme.com"),
				userRecord(t, "u2", "bob", false, false, "bob@acme.com"),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass (no admins → A.8.2 not applicable)", res.Status)
	}
}

func TestManualPresenceRule_PassWhenPresentInWindow(t *testing.T) {
	rule := manualPresenceRule()
	payload := mustMarshal(t, map[string]any{
		"file_present":       true,
		"in_temporal_window": true,
		"file_valid":         true,
	})
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"review_document": {{ID: "iso27001_access_review/2026-Q1", Payload: payload}},
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
			"review_document": {{ID: "iso27001_access_review/2026-Q1", Payload: payload}},
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

func TestManualPresenceRule_FailWhenInvalid(t *testing.T) {
	rule := manualPresenceRule()
	payload := mustMarshal(t, map[string]any{
		"file_present":        true,
		"in_temporal_window":  true,
		"file_valid":          false,
		"validation_failures": []string{"missing_pdf_header (file does not start with %PDF-)"},
	})
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"review_document": {{ID: "iso27001_access_review/2026-Q1", Payload: payload}},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail (file is present and in-window but invalid)", res.Status)
	}
}

func TestEvidenceSignedRule_PassesWhenSigningWorks(t *testing.T) {
	rule := evidenceSignedRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass (sign module is built in)", res.Status)
	}
	if len(res.Violations) != 0 {
		t.Errorf("violations = %v; want none", res.Violations)
	}
}

func TestEvidenceSignedRule_HandlesZeroNow(t *testing.T) {
	rule := evidenceSignedRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass with zero Now (rule fills in time.Now)", res.Status)
	}
}

// userRecord builds a user_record EvidenceRecord with the four fields
// the iso27001 rules read: user_name, mfa_enabled, is_admin, and the
// IdentityKey for cross-source dedup.
func userRecord(t *testing.T, id, name string, mfa, admin bool, identityKey string) core.EvidenceRecord {
	t.Helper()
	payload := mustMarshal(t, map[string]any{
		"user_name":   name,
		"mfa_enabled": mfa,
		"is_admin":    admin,
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
