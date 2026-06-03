package soc2

import (
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// directoryUserTypes is the substitutability set for identity policies:
// any source emitting the v1 or v2 directory_user shape satisfies the
// broad MFA checks. v2-only fields (is_root, has_programmatic_access)
// require the v2 type explicitly.
var directoryUserTypes = []string{"directory_user", "directory_user.v2"}

// cc6Policies returns the CC6 logical-access, network, encryption, and
// threat-detection automated policies.
func cc6Policies() []core.Policy {
	out := make([]core.Policy, 0, 48)
	out = append(out, cc6AccessPolicies()...)
	out = append(out, cc6NetworkPolicies()...)
	out = append(out, cc6EncryptionPolicies()...)
	out = append(out, cc6ThreatPolicies()...)
	return out
}

// cc6AccessPolicies — CC6.1 logical access security.
func cc6AccessPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc6.1.mfa_enforced_all_users", control: "CC6.1", severity: core.SeverityCritical, category: "access", cadence: "daily",
			accepts: directoryUserTypes,
			desc:    "All directory users have multi-factor authentication enabled.",
			rem:     "Enable MFA for every user in each bound identity source.",
			clause:  all(leaf("payload.mfa_enabled", "eq", true), "user {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.mfa_enforced_admins", control: "CC6.1", severity: core.SeverityCritical, category: "access", cadence: "daily",
			accepts: []string{"directory_user.v2"},
			desc:    "All administrator users have MFA enabled.",
			rem:     "Enable MFA for every admin user, or revoke their admin privileges.",
			clause:  allWhere(leaf("payload.is_admin", "eq", true), leaf("payload.mfa_enabled", "eq", true), "admin user {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.root_mfa_enabled", control: "CC6.1", severity: core.SeverityCritical, category: "access", cadence: "daily",
			accepts: []string{"directory_user.v2"},
			desc:    "The root / break-glass account has MFA enabled.",
			rem:     "Enable MFA on the root account (AWS root, GCP org super-admin).",
			clause:  allWhere(leaf("payload.is_root", "eq", true), leaf("payload.mfa_enabled", "eq", true), "root account {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.no_root_access_keys", control: "CC6.1", severity: core.SeverityCritical, category: "access", cadence: "daily",
			accepts: []string{"directory_user.v2"},
			desc:    "The root account has no programmatic access keys.",
			rem:     "Delete all access keys belonging to the root account.",
			clause:  allWhere(leaf("payload.is_root", "eq", true), leaf("payload.has_programmatic_access", "eq", false), "root account {{.payload.display_name}} has programmatic access keys"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.no_direct_iam_policies", control: "CC6.1", severity: core.SeverityMedium, category: "access", cadence: "daily",
			accepts: []string{"directory_user.v2"},
			desc:    "No user has IAM policies attached directly (group-based access only).",
			rem:     "Move directly-attached policies to groups and assign users to those groups.",
			clause:  all(leaf("payload.direct_policy_count", "eq", 0), "user {{.payload.display_name}} has directly-attached IAM policies"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.access_keys_rotated_90d", control: "CC6.1", severity: core.SeverityHigh, category: "access", cadence: "daily",
			accepts: []string{"iam_access_key"},
			desc:    "All active access keys are younger than 90 days.",
			rem:     "Rotate access keys older than 90 days.",
			clause:  allWhere(leaf("payload.is_active", "eq", true), leaf("payload.age_days", "lte", 90), "access key {{.payload.id}} is older than 90 days"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.no_unused_active_keys_90d", control: "CC6.1", severity: core.SeverityMedium, category: "access", cadence: "daily",
			accepts: []string{"iam_access_key"},
			desc:    "All active access keys have been used within the last 90 days.",
			rem:     "Deactivate access keys unused for more than 90 days.",
			// Scope to active AND used keys: last_used_days is omitted for
			// never-used keys (covered by no_never_used_active_keys), and the
			// evaluator errors on an absent referenced field.
			clause: allWhere(allOf(leaf("payload.is_active", "eq", true), leaf("payload.never_used", "eq", false)), leaf("payload.last_used_days", "lte", 90), "access key {{.payload.id}} has not been used in 90 days"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.no_never_used_active_keys", control: "CC6.1", severity: core.SeverityHigh, category: "access", cadence: "daily",
			accepts: []string{"iam_access_key"},
			desc:    "No active access key has never been used.",
			rem:     "Deactivate access keys that have never been used since creation.",
			clause:  noneWhere(leaf("payload.is_active", "eq", true), leaf("payload.never_used", "eq", true), "access key {{.payload.id}} is active but has never been used"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.password_min_length_14", control: "CC6.1", severity: core.SeverityMedium, category: "access", cadence: "daily",
			accepts: []string{"password_policy"},
			desc:    "The account password policy requires at least 14 characters.",
			rem:     "Set the minimum password length to 14 or greater.",
			clause:  all(leaf("payload.min_length", "gte", 14), "password policy minimum length is below 14"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.password_expiry_90d", control: "CC6.1", severity: core.SeverityMedium, category: "access", cadence: "daily",
			accepts: []string{"password_policy"},
			desc:    "Passwords expire within 90 days (or rotation is centrally managed with no expiry).",
			rem:     "Set password expiry to 90 days or fewer.",
			clause:  all(anyOf(leaf("payload.max_age_days", "eq", 0), leaf("payload.max_age_days", "lte", 90)), "password policy expiry exceeds 90 days"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.password_reuse_prevention", control: "CC6.1", severity: core.SeverityLow, category: "access", cadence: "daily",
			accepts: []string{"password_policy"},
			desc:    "The password policy prevents reuse of the last 24 passwords.",
			rem:     "Set password reuse prevention to 24 or greater.",
			clause:  all(leaf("payload.reuse_prevention_count", "gte", 24), "password reuse prevention is below 24"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.password_complexity", control: "CC6.1", severity: core.SeverityMedium, category: "access", cadence: "daily",
			accepts: []string{"password_policy"},
			desc:    "The password policy requires uppercase, lowercase, numbers, and symbols.",
			rem:     "Enable all four character-class requirements in the password policy.",
			clause: all(allOf(
				leaf("payload.requires_uppercase", "eq", true),
				leaf("payload.requires_lowercase", "eq", true),
				leaf("payload.requires_numbers", "eq", true),
				leaf("payload.requires_symbols", "eq", true),
			), "password policy does not require all four character classes"),
		}.policy(),
	}
}

// cc6NetworkPolicies — CC6.6 network access restrictions.
func cc6NetworkPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_ssh", control: "CC6.6", severity: core.SeverityHigh, category: "network", cadence: "daily",
			accepts: []string{"firewall_rule"},
			desc:    "No firewall rule exposes SSH (port 22) to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 22 to known administrative ranges.",
			clause:  unrestrictedPortClause(22),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_rdp", control: "CC6.6", severity: core.SeverityHigh, category: "network", cadence: "daily",
			accepts: []string{"firewall_rule"},
			desc:    "No firewall rule exposes RDP (port 3389) to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 3389.",
			clause:  unrestrictedPortClause(3389),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_mysql", control: "CC6.6", severity: core.SeverityHigh, category: "network", cadence: "daily",
			accepts: []string{"firewall_rule"},
			desc:    "No firewall rule exposes MySQL (port 3306) to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 3306.",
			clause:  unrestrictedPortClause(3306),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_postgres", control: "CC6.6", severity: core.SeverityHigh, category: "network", cadence: "daily",
			accepts: []string{"firewall_rule"},
			desc:    "No firewall rule exposes PostgreSQL (port 5432) to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 5432.",
			clause:  unrestrictedPortClause(5432),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_all_traffic", control: "CC6.6", severity: core.SeverityHigh, category: "network", cadence: "daily",
			accepts: []string{"firewall_rule"},
			desc:    "No firewall rule opens all protocols to the public internet.",
			rem:     "Remove or restrict any all-protocol rule with a 0.0.0.0/0 source.",
			clause:  noneWhere(leaf("payload.protocol", "eq", "all"), leaf("payload.is_unrestricted_ipv4", "eq", true), "firewall rule {{.payload.id}} opens all traffic to 0.0.0.0/0"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.vpc_flow_logs_enabled", control: "CC6.6", severity: core.SeverityMedium, category: "network", cadence: "daily",
			accepts: []string{"network"},
			desc:    "All virtual networks have flow logs enabled.",
			rem:     "Enable flow logs on each VPC / VNet.",
			clause:  all(leaf("payload.flow_logs_enabled", "eq", true), "network {{.payload.name}} does not have flow logs enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_default_vpc_in_use", control: "CC6.6", severity: core.SeverityLow, category: "network", cadence: "daily",
			accepts: []string{"network"},
			desc:    "No default provider-created VPC is in use.",
			rem:     "Migrate workloads off the default VPC and delete it.",
			clause:  none(leaf("payload.is_default", "eq", true), "default network {{.payload.name}} is still present"),
		}.policy(),
	}
}

// cc6EncryptionPolicies — CC6.7 encryption at rest and in transit.
func cc6EncryptionPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc6.7.storage_encryption_at_rest", control: "CC6.7", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"object_storage_bucket"},
			desc:    "All object storage buckets are encrypted at rest.",
			rem:     "Enable default server-side encryption on each bucket.",
			clause:  all(leaf("payload.encryption_at_rest_enabled", "eq", true), "bucket {{.payload.name}} is not encrypted at rest"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.storage_public_access_blocked", control: "CC6.7", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"object_storage_bucket"},
			desc:    "All object storage buckets block public access.",
			rem:     "Enable public-access-block / uniform bucket-level access on each bucket.",
			clause:  all(leaf("payload.public_access_blocked", "eq", true), "bucket {{.payload.name}} does not block public access"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.storage_versioning_enabled", control: "CC6.7", severity: core.SeverityLow, category: "data-protection", cadence: "daily",
			accepts: []string{"object_storage_bucket"},
			desc:    "All object storage buckets have versioning enabled.",
			rem:     "Enable object versioning on each bucket.",
			clause:  all(leaf("payload.versioning_enabled", "eq", true), "bucket {{.payload.name}} does not have versioning enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.database_encryption_at_rest", control: "CC6.7", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "All managed databases are encrypted at rest.",
			rem:     "Re-create unencrypted databases from an encrypted snapshot.",
			clause:  all(leaf("payload.storage_encrypted", "eq", true), "database {{.payload.name}} is not encrypted at rest"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.database_no_public_access", control: "CC6.7", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "No managed database is publicly accessible.",
			rem:     "Disable public accessibility and place databases in private subnets.",
			clause:  all(leaf("payload.publicly_accessible", "eq", false), "database {{.payload.name}} is publicly accessible"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.database_ssl_required", control: "CC6.7", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "All managed databases require SSL/TLS for connections.",
			rem:     "Enforce SSL on each database instance.",
			// Guarded with is_set: a source that cannot determine SSL
			// enforcement (e.g. an RDS engine configured via option groups)
			// omits the field and is skipped here rather than false-failed.
			clause: allWhere(leaf("payload.ssl_required", "is_set", nil), leaf("payload.ssl_required", "eq", true), "database {{.payload.name}} does not require SSL"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.kms_key_rotation_enabled", control: "CC6.7", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"kms_key"},
			desc:    "All customer-managed KMS keys have automatic rotation enabled.",
			rem:     "Enable automatic key rotation on each customer-managed key.",
			clause:  allWhere(leaf("payload.is_customer_managed", "eq", true), leaf("payload.rotation_enabled", "eq", true), "KMS key {{.payload.key_id}} does not have rotation enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.kms_customer_managed_keys", control: "CC6.7", severity: core.SeverityLow, category: "data-protection", cadence: "daily",
			accepts: []string{"kms_key"},
			desc:    "Encryption uses customer-managed KMS keys.",
			rem:     "Migrate workloads to customer-managed keys where compliance requires key control.",
			clause:  all(leaf("payload.is_customer_managed", "eq", true), "KMS key {{.payload.key_id}} is not customer-managed"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.compute_root_volume_encrypted", control: "CC6.7", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"compute_instance"},
			desc:    "All compute instances have encrypted root volumes.",
			rem:     "Re-create instances with encrypted root volumes.",
			clause:  all(leaf("payload.root_volume_encrypted", "eq", true), "instance {{.payload.name}} has an unencrypted root volume"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.kubernetes_secrets_encrypted", control: "CC6.7", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"kubernetes_cluster"},
			desc:    "All Kubernetes clusters encrypt secrets at rest.",
			rem:     "Enable envelope encryption for Kubernetes secrets.",
			clause:  all(leaf("payload.secrets_encryption_enabled", "eq", true), "cluster {{.payload.name}} does not encrypt secrets at rest"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.tls_certificates_not_expiring", control: "CC6.7", severity: core.SeverityMedium, category: "data-protection", cadence: "daily",
			accepts: []string{"tls_certificate"},
			desc:    "No TLS certificate expires within 30 days.",
			rem:     "Renew certificates expiring within 30 days.",
			clause:  all(leaf("payload.days_until_expiry", "gte", 30), "certificate {{.payload.domain}} expires within 30 days"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.tls_auto_renew_enabled", control: "CC6.7", severity: core.SeverityLow, category: "data-protection", cadence: "daily",
			accepts: []string{"tls_certificate"},
			desc:    "All managed TLS certificates have auto-renewal enabled.",
			rem:     "Enable automatic renewal on each managed certificate.",
			// Scope to managed certs: imported certs have no auto-renew concept
			// and omit the field, which would otherwise error the evaluator.
			clause: allWhere(leaf("payload.is_managed", "eq", true), leaf("payload.auto_renew", "eq", true), "certificate {{.payload.domain}} does not have auto-renew enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.secrets_rotation_enabled", control: "CC6.7", severity: core.SeverityMedium, category: "data-protection", cadence: "daily",
			accepts: []string{"secret"},
			desc:    "All managed secrets have automatic rotation enabled.",
			rem:     "Enable automatic rotation on each secret.",
			clause:  all(leaf("payload.rotation_enabled", "eq", true), "secret {{.payload.name}} does not have rotation enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.secrets_kms_encrypted", control: "CC6.7", severity: core.SeverityMedium, category: "data-protection", cadence: "daily",
			accepts: []string{"secret"},
			desc:    "All managed secrets are encrypted with a customer-managed KMS key.",
			rem:     "Encrypt each secret with a customer-managed key.",
			clause:  all(leaf("payload.kms_encrypted", "eq", true), "secret {{.payload.name}} is not encrypted with a customer-managed key"),
		}.policy(),
	}
}

// cc6ThreatPolicies — CC6.8 threat and malware detection.
func cc6ThreatPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc6.8.threat_detection_enabled", control: "CC6.8", severity: core.SeverityHigh, category: "monitoring", cadence: "daily",
			accepts: []string{"threat_detection_service"},
			desc:    "Threat detection is enabled across the account.",
			rem:     "Enable the threat detection service (GuardDuty, SCC, Defender).",
			clause:  all(leaf("payload.is_enabled", "eq", true), "threat detection service {{.payload.name}} is not enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.no_critical_findings_active", control: "CC6.8", severity: core.SeverityCritical, category: "monitoring", cadence: "daily",
			accepts: []string{"vulnerability_finding"},
			desc:    "No CRITICAL vulnerability finding is active.",
			rem:     "Remediate or formally suppress all active CRITICAL findings.",
			clause:  noneWhere(leaf("payload.severity", "eq", "CRITICAL"), leaf("payload.status", "eq", "ACTIVE"), "critical finding {{.payload.id}} is active"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.no_high_findings_unaddressed", control: "CC6.8", severity: core.SeverityHigh, category: "monitoring", cadence: "daily",
			accepts: []string{"vulnerability_finding"},
			desc:    "No HIGH vulnerability finding is active.",
			rem:     "Remediate or formally suppress all active HIGH findings.",
			clause:  noneWhere(leaf("payload.severity", "eq", "HIGH"), leaf("payload.status", "eq", "ACTIVE"), "high finding {{.payload.id}} is active"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.container_scan_on_push", control: "CC6.8", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"container_registry"},
			desc:    "All container registries scan images on push.",
			rem:     "Enable scan-on-push on each container repository.",
			clause:  all(leaf("payload.scan_on_push_enabled", "eq", true), "registry {{.payload.name}} does not scan images on push"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.no_public_container_repos", control: "CC6.8", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"container_registry"},
			desc:    "No container registry is publicly accessible.",
			rem:     "Make public container repositories private.",
			clause:  none(leaf("payload.is_public", "eq", true), "registry {{.payload.name}} is publicly accessible"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.macie_enabled", control: "CC6.8", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"security_service"},
			desc:    "A data loss prevention / classification service is enabled.",
			rem:     "Enable Macie (or an equivalent DLP service) on the account.",
			clause:  anyWhere(leaf("payload.service_type", "eq", "dlp"), leaf("payload.is_enabled", "eq", true), "no DLP service is enabled"),
		}.policy(),
	}
}

// unrestrictedPortClause builds the none-clause that flags any open
// (0.0.0.0/0) TCP ingress rule whose port range covers the target port,
// or that opens all ports (from_port == -1).
func unrestrictedPortClause(port int) core.PassWhenClause {
	filter := allOf(
		leaf("payload.direction", "eq", "ingress"),
		leaf("payload.is_unrestricted_ipv4", "eq", true),
		leaf("payload.protocol", "in", []any{"tcp", "all"}),
	)
	cond := anyOf(
		allOf(leaf("payload.from_port", "lte", port), leaf("payload.to_port", "gte", port)),
		leaf("payload.from_port", "eq", -1),
	)
	return noneWhere(filter, cond, fmt.Sprintf("firewall rule {{.payload.id}} exposes port %d to 0.0.0.0/0", port))
}
