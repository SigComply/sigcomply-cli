package soc2

import (
	"context"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
)

// AWS infrastructure policies — one per source plugin shipped at M7.
// Each policy binds to a single slot consuming the source's emitted
// evidence type and fails on a security-relevant attribute.

// PolicyS3BucketEncrypted is the policy that fails when any S3 bucket
// has no default server-side encryption (SOC 2 CC6.7).
const PolicyS3BucketEncrypted = "soc2.cc6.7.s3_bucket_encrypted"

// PolicyKMSKeyRotation is the policy that fails when any customer-
// managed CMK has automatic rotation disabled (SOC 2 CC6.7).
const PolicyKMSKeyRotation = "soc2.cc6.7.kms_key_rotation_enabled" //gitleaks:allow

// PolicyRDSEncryptionAtRest is the policy that fails when any RDS
// instance has StorageEncrypted=false (SOC 2 CC6.7).
const PolicyRDSEncryptionAtRest = "soc2.cc6.7.rds_encryption_at_rest"

// PolicyEC2NoPublicIP is the policy that fails when any EC2 instance
// has a public IP address (SOC 2 CC6.6 — restrict external network
// access).
const PolicyEC2NoPublicIP = "soc2.cc6.6.ec2_no_public_ip"

// PolicyEKSSecretsEncryption is the policy that fails when any EKS
// cluster lacks envelope encryption for Kubernetes secrets (SOC 2
// CC6.7).
const PolicyEKSSecretsEncryption = "soc2.cc6.7.eks_secrets_encryption" //gitleaks:allow

const (
	ruleIDS3BucketEncrypted    = "rules.soc2.s3_bucket_encrypted.v1"
	ruleIDKMSKeyRotation       = "rules.soc2.kms_key_rotation_enabled.v1"
	ruleIDRDSEncryptionAtRest  = "rules.soc2.rds_encryption_at_rest.v1"
	ruleIDEC2NoPublicIP        = "rules.soc2.ec2_no_public_ip.v1"
	ruleIDEKSSecretsEncryption = "rules.soc2.eks_secrets_encryption.v1"
)

// awsPolicies returns the AWS infrastructure policies wired in this
// release. They share the binary-attribute Go-rule pattern: walk the
// evidence records for one slot, fail on each record whose security
// flag is unset.
func awsPolicies() []core.Policy {
	return []core.Policy{
		{
			ID:          PolicyS3BucketEncrypted,
			Control:     "SOC2.CC6.7",
			Description: "Every S3 bucket has default server-side encryption configured.",
			Remediation: "Enable default encryption (SSE-S3 or SSE-KMS) on the listed buckets via the AWS Console or `aws s3api put-bucket-encryption`.",
			Severity:    core.SeverityHigh,
			Category:    "data-protection",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"buckets": {Type: "s3_bucket", Cardinality: core.SlotExactlyOne, Required: true, Description: "S3 buckets in the configured account"},
			},
			RuleRef: ruleIDS3BucketEncrypted,
		},
		{
			ID:          PolicyKMSKeyRotation,
			Control:     "SOC2.CC6.7",
			Description: "Every customer-managed KMS key has automatic rotation enabled.",
			Remediation: "Enable annual key rotation on the listed CMKs via `aws kms enable-key-rotation --key-id <id>`.",
			Severity:    core.SeverityHigh,
			Category:    "data-protection",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"keys": {Type: "kms_key", Cardinality: core.SlotExactlyOne, Required: true, Description: "KMS keys in the configured region"},
			},
			RuleRef: ruleIDKMSKeyRotation,
		},
		{
			ID:          PolicyRDSEncryptionAtRest,
			Control:     "SOC2.CC6.7",
			Description: "Every RDS DB instance has storage encryption at rest enabled.",
			Remediation: "Re-create the listed RDS instances from an encrypted snapshot, or migrate to a new instance created with StorageEncrypted=true.",
			Severity:    core.SeverityHigh,
			Category:    "data-protection",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"db_instances": {Type: "rds_instance", Cardinality: core.SlotExactlyOne, Required: true, Description: "RDS DB instances"},
			},
			RuleRef: ruleIDRDSEncryptionAtRest,
		},
		{
			ID:          PolicyEC2NoPublicIP,
			Control:     "SOC2.CC6.6",
			Description: "No EC2 instances have public IP addresses.",
			Remediation: "Disassociate public IPs from the listed instances, or relaunch them in a private subnet behind a load balancer / NAT.",
			Severity:    core.SeverityMedium,
			Category:    "network",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"instances": {Type: "ec2_instance", Cardinality: core.SlotExactlyOne, Required: true, Description: "EC2 instances"},
			},
			RuleRef: ruleIDEC2NoPublicIP,
		},
		{
			ID:          PolicyEKSSecretsEncryption,
			Control:     "SOC2.CC6.7",
			Description: "Every EKS cluster has envelope encryption configured for Kubernetes secrets.",
			Remediation: "Enable secrets envelope encryption on the listed EKS clusters via `aws eks associate-encryption-config`.",
			Severity:    core.SeverityHigh,
			Category:    "data-protection",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"clusters": {Type: "eks_cluster", Cardinality: core.SlotExactlyOne, Required: true, Description: "EKS clusters"},
			},
			RuleRef: ruleIDEKSSecretsEncryption,
		},
	}
}

// awsRules returns the Go rules wired for the AWS policies.
func awsRules() []core.Rule {
	return []core.Rule{
		boolAttrRule(ruleIDS3BucketEncrypted, "buckets", "encryption_enabled", "name",
			"S3 bucket %s has no default encryption configured", true),
		// KMS: only customer-managed keys are eligible — AWS-managed keys
		// are managed (and rotated) by AWS automatically.
		kmsRotationRule(),
		boolAttrRule(ruleIDRDSEncryptionAtRest, "db_instances", "storage_encrypted", "db_instance_identifier",
			"RDS instance %s has storage encryption at rest disabled", true),
		// EC2: fail when has_public_ip is true (inverted predicate).
		boolAttrRule(ruleIDEC2NoPublicIP, "instances", "has_public_ip", "instance_id",
			"EC2 instance %s has a public IP address", false),
		boolAttrRule(ruleIDEKSSecretsEncryption, "clusters", "secrets_encryption_enabled", "name",
			"EKS cluster %s has no secrets envelope encryption configured", true),
	}
}

// boolAttrRule builds a generic Go rule that fails when the named slot
// contains an evidence record whose payload boolean does not match
// passWhen. nameKey is the payload field used to name the resource in
// the violation reason (falls back to the record's ID if unset).
func boolAttrRule(ruleID, slot, attr, nameKey, reasonFormat string, passWhen bool) core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleID,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots[slot]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				v, err := payloadBool(r.Payload, attr)
				if err != nil {
					return core.RuleResult{}, err
				}
				if v == passWhen {
					continue
				}
				name, err := payloadString(r.Payload, nameKey)
				if err != nil {
					return core.RuleResult{}, err
				}
				if name == "" {
					name = r.ID
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     fmt.Sprintf(reasonFormat, name),
				})
			}
			status := core.StatusPass
			if len(violations) > 0 {
				status = core.StatusFail
			}
			return core.RuleResult{Status: status, Violations: violations}, nil
		},
	}
}

// kmsRotationRule fails when a customer-managed KMS key has rotation
// disabled. AWS-managed keys (is_customer_managed=false) are skipped —
// AWS rotates them on its own schedule and the API rejects rotation
// queries against them.
func kmsRotationRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDKMSKeyRotation,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["keys"]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				customer, err := payloadBool(r.Payload, "is_customer_managed")
				if err != nil {
					return core.RuleResult{}, err
				}
				if !customer {
					continue
				}
				rot, err := payloadBool(r.Payload, "rotation_enabled")
				if err != nil {
					return core.RuleResult{}, err
				}
				if rot {
					continue
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     fmt.Sprintf("Customer-managed KMS key %s has automatic rotation disabled", r.ID),
				})
			}
			status := core.StatusPass
			if len(violations) > 0 {
				status = core.StatusFail
			}
			return core.RuleResult{Status: status, Violations: violations}, nil
		},
	}
}
