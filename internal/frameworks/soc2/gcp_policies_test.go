package soc2

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// --- gcpIAMNoOwnerRoleForUsers ---

func TestGCPIAMNoOwnerRoleForUsers_PassWhenNoUserOwner(t *testing.T) {
	rule := gcpIAMNoOwnerRoleForUsersRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"iam_bindings": {
				iamBindingRec(t, "roles/owner", "group:admins@acme.com", "group"),
				iamBindingRec(t, "roles/viewer", "user:alice@acme.com", "user"),
				iamBindingRec(t, "roles/editor", "serviceAccount:sa@p.iam", "serviceAccount"),
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

func TestGCPIAMNoOwnerRoleForUsers_FailWhenUserHoldsOwner(t *testing.T) {
	rule := gcpIAMNoOwnerRoleForUsersRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"iam_bindings": {
				iamBindingRec(t, "roles/owner", "user:alice@acme.com", "user"),
				iamBindingRec(t, "roles/owner", "group:admins@acme.com", "group"),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 {
		t.Fatalf("want 1 violation; got %v", res.Violations)
	}
	if !strings.Contains(res.Violations[0].Reason, "user:alice@acme.com") {
		t.Errorf("Reason = %q", res.Violations[0].Reason)
	}
}

func TestGCPIAMNoOwnerRoleForUsers_PassWhenServiceAccountHasOwner(t *testing.T) {
	rule := gcpIAMNoOwnerRoleForUsersRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"iam_bindings": {
				iamBindingRec(t, "roles/owner", "serviceAccount:terraform@p.iam", "serviceAccount"),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass (SAs are allowed to hold owner)", res.Status)
	}
}

// --- gcsBucketUniformAccess ---

func TestGCSBucketUniformAccess_PassWhenAllEnabled(t *testing.T) {
	rule := gcsBucketUniformAccessRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"buckets": {
				bucketRec(t, "alpha", true),
				bucketRec(t, "beta", true),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass", res.Status)
	}
}

func TestGCSBucketUniformAccess_FailWhenAnyDisabled(t *testing.T) {
	rule := gcsBucketUniformAccessRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"buckets": {
				bucketRec(t, "alpha", true),
				bucketRec(t, "legacy", false),
				bucketRec(t, "other-legacy", false),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 2 {
		t.Errorf("want 2 violations; got %d", len(res.Violations))
	}
	for _, v := range res.Violations {
		if !strings.Contains(v.Reason, "uniform bucket-level access disabled") {
			t.Errorf("Reason = %q", v.Reason)
		}
	}
}

// --- computeNoDefaultServiceAccount ---

func TestComputeNoDefaultServiceAccount_PassWhenAllCustom(t *testing.T) {
	rule := computeNoDefaultServiceAccountRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"instances": {
				computeInstanceRec(t, "web-1", false),
				computeInstanceRec(t, "worker-1", false),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass", res.Status)
	}
}

func TestComputeNoDefaultServiceAccount_FailWhenAnyUsesDefault(t *testing.T) {
	rule := computeNoDefaultServiceAccountRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"instances": {
				computeInstanceRec(t, "web-1", false),
				computeInstanceRec(t, "legacy-vm", true),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "legacy-vm" {
		t.Errorf("violations = %v", res.Violations)
	}
}

// --- cloudSQLRequireSSL ---

func TestCloudSQLRequireSSL_PassWhenAllRequireSSL(t *testing.T) {
	rule := cloudSQLRequireSSLRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"instances": {
				sqlInstanceRec(t, "primary", true),
				sqlInstanceRec(t, "replica", true),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass", res.Status)
	}
}

func TestCloudSQLRequireSSL_FailWhenAnyMissing(t *testing.T) {
	rule := cloudSQLRequireSSLRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"instances": {
				sqlInstanceRec(t, "primary", true),
				sqlInstanceRec(t, "dev-db", false),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "dev-db" {
		t.Errorf("violations = %v", res.Violations)
	}
	if !strings.Contains(res.Violations[0].Reason, "does not require SSL") {
		t.Errorf("Reason = %q", res.Violations[0].Reason)
	}
}

// --- registration coverage ---

func TestGCPPolicies_RegisteredInSet(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for _, p := range gcpPolicies() {
		if _, ok := set.Policies.Lookup(p.ID); !ok {
			t.Errorf("policy %q not registered", p.ID)
		}
	}
	wantRules := []string{
		ruleIDGCPIAMNoOwnerRoleForUsers,
		ruleIDGCSBucketUniformAccess,
		ruleIDComputeNoDefaultServiceAccount,
		ruleIDCloudSQLRequireSSL,
	}
	for _, r := range wantRules {
		if _, ok := set.Rules.Lookup(r); !ok {
			t.Errorf("rule %q not registered", r)
		}
	}
}

func TestGCPPolicies_ReferenceKnownControls(t *testing.T) {
	controlIDs := map[string]bool{}
	for _, c := range Controls() {
		controlIDs[c.ID] = true
	}
	for _, p := range gcpPolicies() {
		if !controlIDs[p.Control] {
			t.Errorf("policy %q references unknown control %q", p.ID, p.Control)
		}
	}
}

// --- shared test helpers ---

func iamBindingRec(t *testing.T, role, member, memberType string) core.EvidenceRecord {
	t.Helper()
	payload := gcpMustMarshal(t, map[string]any{
		"role":        role,
		"member":      member,
		"member_type": memberType,
	})
	return core.EvidenceRecord{
		Type:    "gcp_iam_binding",
		ID:      role + "|" + member,
		Payload: payload,
	}
}

func bucketRec(t *testing.T, name string, uniformAccess bool) core.EvidenceRecord {
	t.Helper()
	payload := gcpMustMarshal(t, map[string]any{
		"name":                        name,
		"uniform_bucket_level_access": uniformAccess,
	})
	return core.EvidenceRecord{Type: "gcs_bucket", ID: name, Payload: payload}
}

func computeInstanceRec(t *testing.T, name string, usesDefaultSA bool) core.EvidenceRecord {
	t.Helper()
	payload := gcpMustMarshal(t, map[string]any{
		"name":                         name,
		"uses_default_service_account": usesDefaultSA,
	})
	return core.EvidenceRecord{Type: "compute_instance", ID: name, Payload: payload}
}

func sqlInstanceRec(t *testing.T, name string, requireSSL bool) core.EvidenceRecord {
	t.Helper()
	payload := gcpMustMarshal(t, map[string]any{
		"name":        name,
		"require_ssl": requireSSL,
	})
	return core.EvidenceRecord{Type: "cloudsql_instance", ID: name, Payload: payload}
}

func gcpMustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}
