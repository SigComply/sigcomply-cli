// This file (gcp_policies.go) holds the four representative GCP SOC 2
// policies authored alongside the gcp.iam / gcp.storage / gcp.compute /
// gcp.sql source plugins. Each policy maps one collector to one rule;
// the rules are deliberately small Go closures matching the pattern in
// mfaEnforcedRule (see framework.go).
//
// The hand-rolled bool/string accessors (payloadBool, payloadString)
// from framework.go are reused here.

package soc2

import (
	"context"
	"fmt"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
)

// GCP policy IDs — exported so tests and other packages can reference
// them by symbol rather than string-literal. PolicyObjectStorageBlocked
// is cross-vendor (it accepts object_storage_bucket from any cloud
// source — S3, GCS, Azure Blob) even though it lives in this file for
// historical reasons; the gcs_bucket_uniform_access policy it replaces
// was GCS-only.
const (
	PolicyGCPIAMNoOwnerRoleForUsers        = "soc2.cc6.1.gcp_iam_no_owner_role_for_users"
	PolicyObjectStoragePublicAccessBlocked = "soc2.cc6.7.object_storage_public_access_blocked"
	PolicyComputeNoDefaultServiceAccount   = "soc2.cc6.6.compute_no_default_service_account"
	PolicyCloudSQLRequireSSL               = "soc2.cc6.7.cloudsql_require_ssl"
)

// GCP rule IDs.
const (
	ruleIDGCPIAMNoOwnerRoleForUsers        = "rules.soc2.gcp_iam_no_owner_role_for_users.v1"
	ruleIDObjectStoragePublicAccessBlocked = "rules.soc2.object_storage_public_access_blocked.v1"
	ruleIDComputeNoDefaultServiceAccount   = "rules.soc2.compute_no_default_service_account.v1"
	ruleIDCloudSQLRequireSSL               = "rules.soc2.cloudsql_require_ssl.v1"
)

// gcpPolicies returns the four representative GCP SOC 2 policies.
// Appended to the framework's Policies() output and registered via
// the standard Register flow.
//
//nolint:dupl // each policy spec is a deliberately-declarative config block; collapsing them would obscure rather than clarify
func gcpPolicies() []core.Policy {
	return []core.Policy{
		{
			ID:           PolicyGCPIAMNoOwnerRoleForUsers,
			Control:      "SOC2.CC6.1",
			Description:  "No individual user account holds the project-level roles/owner binding.",
			Remediation:  "Remove the roles/owner binding from any user: principal. Use group-based admin access (roles/owner on an admins@ group) instead.",
			Severity:     core.SeverityHigh,
			Category:     "access",
			Cadence:      "daily",
			OnPush:       true,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				"iam_bindings": {Accepts: []string{"gcp_iam_binding"}, Cardinality: core.SlotExactlyOne, Required: true, Description: "Project IAM policy bindings"},
			},
			RuleRef: ruleIDGCPIAMNoOwnerRoleForUsers,
		},
		{
			ID:           PolicyObjectStoragePublicAccessBlocked,
			Control:      "SOC2.CC6.7",
			Description:  "Every object storage bucket across every bound cloud has public access blocked at the bucket-configuration layer.",
			Remediation:  "Block public access on the listed buckets (S3: set all four PublicAccessBlock flags; GCS: enable uniform bucket-level access AND set PublicAccessPrevention=enforced; Azure Blob: set allow_blob_public_access=false on the storage account).",
			Severity:     core.SeverityMedium,
			Category:     "data-protection",
			Cadence:      "daily",
			OnPush:       true,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				"buckets": {Accepts: []string{"object_storage_bucket"}, Cardinality: core.SlotOneOrMore, Required: true, Description: "Object storage buckets across all bound clouds"},
			},
			RuleRef: ruleIDObjectStoragePublicAccessBlocked,
		},
		{
			ID:           PolicyComputeNoDefaultServiceAccount,
			Control:      "SOC2.CC6.6",
			Description:  "No Compute Engine VM uses the project's default service account.",
			Remediation:  "Recreate the listed VMs with a custom service account scoped to the minimum permissions required.",
			Severity:     core.SeverityHigh,
			Category:     "access",
			Cadence:      "daily",
			OnPush:       true,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				"instances": {Accepts: []string{"compute_instance"}, Cardinality: core.SlotExactlyOne, Required: true, Description: "Compute Engine instances"},
			},
			RuleRef: ruleIDComputeNoDefaultServiceAccount,
		},
		{
			ID:           PolicyCloudSQLRequireSSL,
			Control:      "SOC2.CC6.7",
			Description:  "All Cloud SQL instances require SSL/TLS for connections.",
			Remediation:  "Set requireSsl=true on each listed instance via the Cloud SQL Admin API or `gcloud sql instances patch`.",
			Severity:     core.SeverityHigh,
			Category:     "data-protection",
			Cadence:      "daily",
			OnPush:       true,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				"instances": {Accepts: []string{"cloudsql_instance"}, Cardinality: core.SlotExactlyOne, Required: true, Description: "Cloud SQL instances"},
			},
			RuleRef: ruleIDCloudSQLRequireSSL,
		},
	}
}

// gcpRules returns the four rule implementations for the GCP policies.
func gcpRules() []core.Rule {
	return []core.Rule{
		gcpIAMNoOwnerRoleForUsersRule(),
		objectStoragePublicAccessBlockedRule(),
		computeNoDefaultServiceAccountRule(),
		cloudSQLRequireSSLRule(),
	}
}

// gcpIAMNoOwnerRoleForUsersRule fails when any binding grants
// roles/owner to a user: member. Service-account, group, and domain
// members are allowed (group-managed owner access is acceptable).
func gcpIAMNoOwnerRoleForUsersRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDGCPIAMNoOwnerRoleForUsers,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["iam_bindings"]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				role, err := payloadString(r.Payload, "role")
				if err != nil {
					return core.RuleResult{}, err
				}
				if role != "roles/owner" {
					continue
				}
				memberType, err := payloadString(r.Payload, "member_type")
				if err != nil {
					return core.RuleResult{}, err
				}
				if memberType != "user" {
					continue
				}
				member, err := payloadString(r.Payload, "member")
				if err != nil {
					return core.RuleResult{}, err
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     fmt.Sprintf("user %s holds roles/owner — move to a group-based binding", member),
				})
			}
			return resultFor(violations), nil
		},
	}
}

// objectStoragePublicAccessBlockedRule fails when any object_storage_bucket
// reports public_access_blocked=false. Plugins (aws.s3, gcp.storage,
// future azure.blob) compute the boolean from provider-specific
// bucket-policy / ACL / public-access-prevention settings.
func objectStoragePublicAccessBlockedRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDObjectStoragePublicAccessBlocked,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["buckets"]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				blocked, err := payloadBool(r.Payload, "public_access_blocked")
				if err != nil {
					return core.RuleResult{}, err
				}
				if blocked {
					continue
				}
				name, err := payloadString(r.Payload, "name")
				if err != nil {
					return core.RuleResult{}, err
				}
				if name == "" {
					name = r.ID
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     fmt.Sprintf("object storage bucket %s does not block public access at the bucket-configuration layer", name),
				})
			}
			return resultFor(violations), nil
		},
	}
}

// computeNoDefaultServiceAccountRule fails when any VM uses the
// project's default Compute service account.
func computeNoDefaultServiceAccountRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDComputeNoDefaultServiceAccount,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["instances"]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				usesDefault, err := payloadBool(r.Payload, "uses_default_service_account")
				if err != nil {
					return core.RuleResult{}, err
				}
				if !usesDefault {
					continue
				}
				name, err := payloadString(r.Payload, "name")
				if err != nil {
					return core.RuleResult{}, err
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     fmt.Sprintf("instance %s uses the default Compute service account", strings.TrimSpace(name)),
				})
			}
			return resultFor(violations), nil
		},
	}
}

// cloudSQLRequireSSLRule fails when any Cloud SQL instance has
// requireSsl=false. SSL-mode-only configurations (ENCRYPTED_ONLY,
// TRUSTED_CLIENT_CERTIFICATE_REQUIRED) are not yet recognized as
// equivalent — this is intentionally strict for the v1 policy.
func cloudSQLRequireSSLRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDCloudSQLRequireSSL,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["instances"]
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				require, err := payloadBool(r.Payload, "require_ssl")
				if err != nil {
					return core.RuleResult{}, err
				}
				if require {
					continue
				}
				name, err := payloadString(r.Payload, "name")
				if err != nil {
					return core.RuleResult{}, err
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     fmt.Sprintf("Cloud SQL instance %s does not require SSL", name),
				})
			}
			return resultFor(violations), nil
		},
	}
}

// resultFor packages a violations slice into a RuleResult — pass when
// empty, fail otherwise. Trivial helper extracted so the four rules
// above don't repeat the same five-line tail.
func resultFor(violations []core.Violation) core.RuleResult {
	if len(violations) == 0 {
		return core.RuleResult{Status: core.StatusPass, Violations: violations}
	}
	return core.RuleResult{Status: core.StatusFail, Violations: violations}
}
