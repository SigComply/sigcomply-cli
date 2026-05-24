package soc2

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// rulesByID returns awsRules() keyed by their rule ID so tests can
// fetch by name without depending on positional order.
func rulesByID(t *testing.T) map[string]core.Rule {
	t.Helper()
	m := make(map[string]core.Rule)
	for _, r := range awsRules() {
		m[r.ID()] = r
	}
	return m
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestAWSPolicies_AllConsumeDistinctSlots(t *testing.T) {
	policies := awsPolicies()
	if len(policies) != 5 {
		t.Fatalf("awsPolicies() = %d; want 5", len(policies))
	}
	wantIDs := map[string]string{
		PolicyS3BucketEncrypted:    "s3_bucket",
		PolicyKMSKeyRotation:       "kms_key",
		PolicyRDSEncryptionAtRest:  "rds_instance",
		PolicyEC2NoPublicIP:        "ec2_instance",
		PolicyEKSSecretsEncryption: "eks_cluster",
	}
	for _, p := range policies {
		wantType, ok := wantIDs[p.ID]
		if !ok {
			t.Errorf("unexpected policy %q", p.ID)
			continue
		}
		if len(p.Slots) != 1 {
			t.Errorf("%s has %d slots; want 1", p.ID, len(p.Slots))
		}
		found := false
		for _, s := range p.Slots {
			if s.Type == wantType {
				found = true
			}
		}
		if !found {
			t.Errorf("%s slot type != %q", p.ID, wantType)
		}
		if p.RuleRef == "" {
			t.Errorf("%s RuleRef empty", p.ID)
		}
	}
}

// --- S3 ---

func TestS3BucketEncrypted_PassWhenAllEncrypted(t *testing.T) {
	rule := rulesByID(t)[ruleIDS3BucketEncrypted]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"buckets": {
				{ID: "alpha", Payload: mustJSON(t, map[string]any{"name": "alpha", "encryption_enabled": true})},
				{ID: "beta", Payload: mustJSON(t, map[string]any{"name": "beta", "encryption_enabled": true})},
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
		t.Errorf("violations = %v", res.Violations)
	}
}

func TestS3BucketEncrypted_FailWhenBucketUnencrypted(t *testing.T) {
	rule := rulesByID(t)[ruleIDS3BucketEncrypted]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"buckets": {
				{ID: "alpha", Payload: mustJSON(t, map[string]any{"name": "alpha", "encryption_enabled": true})},
				{ID: "leaky", Payload: mustJSON(t, map[string]any{"name": "leaky", "encryption_enabled": false})},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "leaky" {
		t.Errorf("violations = %v", res.Violations)
	}
}

// --- KMS ---

func TestKMSKeyRotation_PassWhenRotationOnForCustomerKey(t *testing.T) {
	rule := rulesByID(t)[ruleIDKMSKeyRotation]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"keys": {
				{ID: "k1", Payload: mustJSON(t, map[string]any{"is_customer_managed": true, "rotation_enabled": true})},
				// AWS-managed key — rotation not user-controlled, must be skipped.
				{ID: "k2", Payload: mustJSON(t, map[string]any{"is_customer_managed": false, "rotation_enabled": false})},
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

func TestKMSKeyRotation_FailWhenCustomerKeyMissingRotation(t *testing.T) {
	rule := rulesByID(t)[ruleIDKMSKeyRotation]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"keys": {
				{ID: "k1", Payload: mustJSON(t, map[string]any{"is_customer_managed": true, "rotation_enabled": false})},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "k1" {
		t.Errorf("violations = %v", res.Violations)
	}
}

// --- RDS ---

func TestRDSEncryptionAtRest_PassWhenEncrypted(t *testing.T) {
	rule := rulesByID(t)[ruleIDRDSEncryptionAtRest]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"db_instances": {
				{ID: "db1", Payload: mustJSON(t, map[string]any{"db_instance_identifier": "db1", "storage_encrypted": true})},
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

func TestRDSEncryptionAtRest_FailWhenUnencrypted(t *testing.T) {
	rule := rulesByID(t)[ruleIDRDSEncryptionAtRest]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"db_instances": {
				{ID: "db1", Payload: mustJSON(t, map[string]any{"db_instance_identifier": "db1", "storage_encrypted": true})},
				{ID: "db2", Payload: mustJSON(t, map[string]any{"db_instance_identifier": "db2", "storage_encrypted": false})},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "db2" {
		t.Errorf("violations = %v", res.Violations)
	}
}

// --- EC2 ---

func TestEC2NoPublicIP_PassWhenAllPrivate(t *testing.T) {
	rule := rulesByID(t)[ruleIDEC2NoPublicIP]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"instances": {
				{ID: "i-1", Payload: mustJSON(t, map[string]any{"instance_id": "i-1", "has_public_ip": false})},
				{ID: "i-2", Payload: mustJSON(t, map[string]any{"instance_id": "i-2", "has_public_ip": false})},
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

func TestEC2NoPublicIP_FailWhenInstanceHasPublicIP(t *testing.T) {
	rule := rulesByID(t)[ruleIDEC2NoPublicIP]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"instances": {
				{ID: "i-1", Payload: mustJSON(t, map[string]any{"instance_id": "i-1", "has_public_ip": false})},
				{ID: "i-exposed", Payload: mustJSON(t, map[string]any{"instance_id": "i-exposed", "has_public_ip": true})},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "i-exposed" {
		t.Errorf("violations = %v", res.Violations)
	}
}

// --- EKS ---

func TestEKSSecretsEncryption_PassWhenEnabled(t *testing.T) {
	rule := rulesByID(t)[ruleIDEKSSecretsEncryption]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"clusters": {
				{ID: "alpha", Payload: mustJSON(t, map[string]any{"name": "alpha", "secrets_encryption_enabled": true})},
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

func TestEKSSecretsEncryption_FailWhenMissing(t *testing.T) {
	rule := rulesByID(t)[ruleIDEKSSecretsEncryption]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"clusters": {
				{ID: "exposed", Payload: mustJSON(t, map[string]any{"name": "exposed", "secrets_encryption_enabled": false})},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "exposed" {
		t.Errorf("violations = %v", res.Violations)
	}
}

// --- boolAttrRule helper edge cases ---

func TestBoolAttrRule_FallsBackToRecordIDWhenNameKeyAbsent(t *testing.T) {
	rule := rulesByID(t)[ruleIDS3BucketEncrypted]
	// Provide a payload that lacks the "name" field; boolAttrRule should
	// fall back to the record's ID for the violation reason.
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"buckets": {
				{ID: "fallback-id", Payload: mustJSON(t, map[string]any{"encryption_enabled": false})},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(res.Violations) != 1 {
		t.Fatalf("violations = %d; want 1", len(res.Violations))
	}
	if res.Violations[0].Reason == "" || res.Violations[0].ResourceID != "fallback-id" {
		t.Errorf("violation didn't fall back to record ID: %+v", res.Violations[0])
	}
}

func TestBoolAttrRule_MissingAttrTreatedAsFalse(t *testing.T) {
	// Buckets policy: passWhen=true, attr=encryption_enabled. A payload
	// without the attribute deserializes to false → violation.
	rule := rulesByID(t)[ruleIDS3BucketEncrypted]
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"buckets": {
				{ID: "no-attr", Payload: mustJSON(t, map[string]any{"name": "no-attr"})},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail (missing attr treated as false)", res.Status)
	}
}
