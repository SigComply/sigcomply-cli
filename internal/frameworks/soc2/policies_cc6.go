package soc2

import (
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// directoryUserTypes is the substitutability set for identity policies:
// any source emitting the v1 or v2 directory_user shape satisfies the
// broad MFA checks. v2-only fields (is_root, has_programmatic_access)
// require the v2 type explicitly.
var directoryUserTypes = []string{etDirectoryUser, etDirectoryUserV2}

// cc6Policies returns the CC6 logical-access, network, encryption, and
// threat-detection automated policies.
func cc6Policies() []core.Policy {
	out := make([]core.Policy, 0, 48)
	out = append(out, cc6AccessPolicies()...)
	out = append(out, cc6RosterPolicies()...)
	out = append(out, cc6NetworkPolicies()...)
	out = append(out, cc6EncryptionPolicies()...)
	out = append(out, cc6ThreatPolicies()...)
	return out
}

// cc6AccessPolicies — CC6.1 logical access security.
func cc6AccessPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc6.1.mfa_enforced_all_users", control: ctrlCC61, severity: core.SeverityCritical, category: catAccess, cadence: cadenceDaily,
			accepts: directoryUserTypes,
			desc:    "All directory users have multi-factor authentication enabled.",
			rem:     "Enable MFA for every user in each bound identity source.",
			clause:  all(leaf("payload.mfa_enabled", "eq", true), "user {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.mfa_enforced_admins", control: ctrlCC61, severity: core.SeverityCritical, category: catAccess, cadence: cadenceDaily,
			// Requires is_admin AND mfa_enabled, phrased as none(admin AND
			// no-MFA). A source that does NOT populate is_admin (e.g. Okta,
			// which needs a per-user roles call to determine admin status)
			// ERRORS, which is the intended way to surface a coverage gap.
			// A bare filter on is_admin would now error too — it no longer
			// silently empties the set — but the none() phrasing keeps the
			// requirement legible as one predicate. AWS IAM and GitHub
			// populate is_admin and evaluate correctly.
			accepts: directoryUserTypes,
			desc:    "All administrator users have MFA enabled.",
			rem:     "Enable MFA for every admin user, or revoke their admin privileges.",
			clause:  none(allOf(leaf("payload.is_admin", "eq", true), leaf("payload.mfa_enabled", "eq", false)), "admin user {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.root_mfa_enabled", control: ctrlCC61, severity: core.SeverityCritical, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etDirectoryUserV2},
			desc:    "The root / break-glass account has MFA enabled.",
			rem:     "Enable MFA on the root account (AWS root, GCP org super-admin).",
			clause:  allWhere(leaf("payload.is_root", "eq", true), leaf("payload.mfa_enabled", "eq", true), "root account {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.no_root_access_keys", control: ctrlCC61, severity: core.SeverityCritical, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etDirectoryUserV2},
			desc:    "The root account has no programmatic access keys.",
			rem:     "Delete all access keys belonging to the root account.",
			clause:  allWhere(leaf("payload.is_root", "eq", true), leaf("payload.has_programmatic_access", "eq", false), "root account {{.payload.display_name}} has programmatic access keys"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.no_direct_iam_policies", control: ctrlCC61, severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etDirectoryUserV2},
			desc:    "No user has IAM policies attached directly (group-based access only).",
			rem:     "Move directly-attached policies to groups and assign users to those groups.",
			clause:  all(leaf("payload.direct_policy_count", "eq", 0), "user {{.payload.display_name}} has directly-attached IAM policies"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.access_keys_rotated_90d", control: ctrlCC61, severity: core.SeverityHigh, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etIAMAccessKey},
			desc:    "All active access keys are younger than 90 days.",
			rem:     "Rotate access keys older than 90 days.",
			clause:  allWhere(leaf("payload.is_active", "eq", true), leaf("payload.age_days", "lte", 90), "access key {{.payload.id}} is older than 90 days"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.no_unused_active_keys_90d", control: ctrlCC61, severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etIAMAccessKey},
			desc:    "All active access keys have been used within the last 90 days.",
			rem:     "Deactivate access keys unused for more than 90 days.",
			// Scope to active AND used keys: last_used_days is omitted for
			// never-used keys (covered by no_never_used_active_keys), and the
			// evaluator errors on an absent referenced field.
			clause: allWhere(allOf(leaf("payload.is_active", "eq", true), leaf("payload.never_used", "eq", false)), leaf("payload.last_used_days", "lte", 90), "access key {{.payload.id}} has not been used in 90 days"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.no_never_used_active_keys", control: ctrlCC61, severity: core.SeverityHigh, category: catAccess, cadence: cadenceDaily,
			accepts: []string{etIAMAccessKey},
			desc:    "No active access key has never been used.",
			rem:     "Deactivate access keys that have never been used since creation.",
			clause:  noneWhere(leaf("payload.is_active", "eq", true), leaf("payload.never_used", "eq", true), "access key {{.payload.id}} is active but has never been used"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.password_min_length_14", control: ctrlCC61, severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: passwordPolicyTypes,
			desc:    "The account password policy requires at least 14 characters.",
			rem:     "Set the minimum password length to 14 or greater.",
			clause:  passwordLengthClause(14),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.password_expiry_90d", control: ctrlCC61, severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: passwordPolicyTypes,
			desc:    "Passwords expire within 90 days (or rotation is centrally managed with no expiry).",
			rem:     "Set password expiry to 90 days or fewer.",
			clause:  passwordExpiryClause(90),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.password_reuse_prevention", control: ctrlCC61, severity: core.SeverityLow, category: catAccess, cadence: cadenceDaily,
			accepts: passwordPolicyTypes,
			desc:    "The password policy prevents password reuse.",
			rem:     "Enable password history so a previous password cannot be set again.",
			clause:  passwordReusePreventedClause(),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.1.password_complexity", control: ctrlCC61, severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: passwordPolicyTypes,
			desc:    "A password-strength control is enforced — either every character class is required, or the platform's own strength rating is.",
			rem:     "Require uppercase, lowercase, numbers and symbols, or turn on the platform's strong-password enforcement.",
			clause:  passwordStrengthEnforcedClause(),
		}.policy(),
	}
}

// cc6NetworkPolicies — CC6.6 network access restrictions.
func cc6NetworkPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_ssh", control: ctrlCC66, severity: core.SeverityHigh, category: catNetwork, cadence: cadenceDaily,
			accepts: []string{etFirewallRule},
			desc:    "No firewall rule exposes SSH (port 22) to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 22 to known administrative ranges.",
			clause:  unrestrictedPortClause(22),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_rdp", control: ctrlCC66, severity: core.SeverityHigh, category: catNetwork, cadence: cadenceDaily,
			accepts: []string{etFirewallRule},
			desc:    "No firewall rule exposes RDP (port 3389) to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 3389.",
			clause:  unrestrictedPortClause(3389),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_mysql", control: ctrlCC66, severity: core.SeverityHigh, category: catNetwork, cadence: cadenceDaily,
			accepts: []string{etFirewallRule},
			desc:    "No firewall rule exposes MySQL (port 3306) to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 3306.",
			clause:  unrestrictedPortClause(3306),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_postgres", control: ctrlCC66, severity: core.SeverityHigh, category: catNetwork, cadence: cadenceDaily,
			accepts: []string{etFirewallRule},
			desc:    "No firewall rule exposes PostgreSQL (port 5432) to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 5432.",
			clause:  unrestrictedPortClause(5432),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_unrestricted_all_traffic", control: ctrlCC66, severity: core.SeverityHigh, category: catNetwork, cadence: cadenceDaily,
			accepts: []string{etFirewallRule},
			desc:    "No firewall rule opens all protocols to the public internet.",
			rem:     "Remove or restrict any all-protocol rule with a 0.0.0.0/0 source.",
			clause:  noneWhere(leaf("payload.protocol", "eq", "all"), leaf("payload.is_unrestricted_ipv4", "eq", true), "firewall rule {{.payload.id}} opens all traffic to 0.0.0.0/0"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.vpc_flow_logs_enabled", control: ctrlCC66, severity: core.SeverityMedium, category: catNetwork, cadence: cadenceDaily,
			accepts: []string{"network"},
			desc:    "All virtual networks have flow logs enabled.",
			rem:     "Enable flow logs on each VPC / VNet.",
			clause:  all(leaf("payload.flow_logs_enabled", "eq", true), "network {{.payload.name}} does not have flow logs enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.6.no_default_vpc_in_use", control: ctrlCC66, severity: core.SeverityLow, category: catNetwork, cadence: cadenceDaily,
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
			id: "soc2.cc6.7.storage_encryption_at_rest", control: ctrlCC67, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etObjectStorageBucket},
			desc:    "All object storage buckets are encrypted at rest.",
			rem:     "Enable default server-side encryption on each bucket.",
			clause:  all(leaf("payload.encryption_at_rest_enabled", "eq", true), "bucket {{.payload.name}} is not encrypted at rest"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.storage_public_access_blocked", control: ctrlCC67, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etObjectStorageBucket},
			desc:    "All object storage buckets block public access.",
			rem:     "Enable public-access-block / uniform bucket-level access on each bucket.",
			clause:  all(leaf("payload.public_access_blocked", "eq", true), "bucket {{.payload.name}} does not block public access"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.storage_versioning_enabled", control: ctrlCC67, severity: core.SeverityLow, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etObjectStorageBucket},
			desc:    "All object storage buckets have versioning enabled.",
			rem:     "Enable object versioning on each bucket.",
			clause:  all(leaf("payload.versioning_enabled", "eq", true), "bucket {{.payload.name}} does not have versioning enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.database_encryption_at_rest", control: ctrlCC67, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etManagedDatabaseInstance},
			desc:    "All managed databases are encrypted at rest.",
			rem:     "Re-create unencrypted databases from an encrypted snapshot.",
			clause:  all(leaf("payload.storage_encrypted", "eq", true), "database {{.payload.name}} is not encrypted at rest"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.database_no_public_access", control: ctrlCC67, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etManagedDatabaseInstance},
			desc:    "No managed database is publicly accessible.",
			rem:     "Disable public accessibility and place databases in private subnets.",
			clause:  all(leaf("payload.publicly_accessible", "eq", false), "database {{.payload.name}} is publicly accessible"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.database_ssl_required", control: ctrlCC67, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etManagedDatabaseInstance},
			desc:    "All managed databases require SSL/TLS for connections.",
			rem:     "Enforce SSL on each database instance.",
			// Guarded with is_set: a source that cannot determine SSL
			// enforcement (e.g. an RDS engine configured via option groups)
			// omits the field and is skipped here rather than false-failed.
			clause: allWhere(leaf("payload.ssl_required", "is_set", nil), leaf("payload.ssl_required", "eq", true), "database {{.payload.name}} does not require SSL"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.kms_key_rotation_enabled", control: ctrlCC67, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{"kms_key"},
			desc:    "All customer-managed KMS keys have automatic rotation enabled.",
			rem:     "Enable automatic key rotation on each customer-managed key.",
			clause:  allWhere(allOf(isSet("payload.is_customer_managed"), leaf("payload.is_customer_managed", "eq", true)), leaf("payload.rotation_enabled", "eq", true), "KMS key {{.payload.key_id}} does not have rotation enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.kms_customer_managed_keys", control: ctrlCC67, severity: core.SeverityLow, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{"kms_key"},
			desc:    "Encryption uses customer-managed KMS keys.",
			rem:     "Migrate workloads to customer-managed keys where compliance requires key control.",
			clause:  all(leaf("payload.is_customer_managed", "eq", true), "KMS key {{.payload.key_id}} is not customer-managed"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.compute_root_volume_encrypted", control: ctrlCC67, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{"compute_instance"},
			desc:    "All compute instances have encrypted root volumes.",
			rem:     "Re-create instances with encrypted root volumes.",
			clause:  all(leaf("payload.root_volume_encrypted", "eq", true), "instance {{.payload.name}} has an unencrypted root volume"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.kubernetes_secrets_encrypted", control: ctrlCC67, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{"kubernetes_cluster"},
			desc:    "All Kubernetes clusters encrypt secrets at rest.",
			rem:     "Enable envelope encryption for Kubernetes secrets.",
			clause:  all(leaf("payload.secrets_encryption_enabled", "eq", true), "cluster {{.payload.name}} does not encrypt secrets at rest"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.tls_certificates_not_expiring", control: ctrlCC67, severity: core.SeverityMedium, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{"tls_certificate"},
			desc:    "No TLS certificate expires within 30 days.",
			rem:     "Renew certificates expiring within 30 days.",
			clause:  all(leaf("payload.days_until_expiry", "gte", 30), "certificate {{.payload.domain}} expires within 30 days"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.tls_auto_renew_enabled", control: ctrlCC67, severity: core.SeverityLow, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{"tls_certificate"},
			desc:    "All managed TLS certificates have auto-renewal enabled.",
			rem:     "Enable automatic renewal on each managed certificate.",
			// Scope to managed certs: imported certs have no auto-renew concept
			// and omit the field, which would otherwise error the evaluator.
			clause: allWhere(leaf("payload.is_managed", "eq", true), leaf("payload.auto_renew", "eq", true), "certificate {{.payload.domain}} does not have auto-renew enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.secrets_rotation_enabled", control: ctrlCC67, severity: core.SeverityMedium, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{"secret"},
			desc:    "All managed secrets have automatic rotation enabled.",
			rem:     "Enable automatic rotation on each secret.",
			clause:  all(leaf("payload.rotation_enabled", "eq", true), "secret {{.payload.name}} does not have rotation enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.7.secrets_kms_encrypted", control: ctrlCC67, severity: core.SeverityMedium, category: catDataProtection, cadence: cadenceDaily,
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
			id: "soc2.cc6.8.threat_detection_enabled", control: ctrlCC68, severity: core.SeverityHigh, category: catMonitoring, cadence: cadenceDaily,
			accepts: []string{"threat_detection_service"},
			desc:    "Threat detection is enabled across the account.",
			rem:     "Enable the threat detection service (GuardDuty, SCC, Defender).",
			clause:  all(leaf("payload.is_enabled", "eq", true), "threat detection service {{.payload.name}} is not enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.no_critical_findings_active", control: ctrlCC68, severity: core.SeverityCritical, category: catMonitoring, cadence: cadenceDaily,
			accepts: []string{etVulnerabilityFinding},
			desc:    "No CRITICAL vulnerability finding is active.",
			rem:     "Remediate or formally suppress all active CRITICAL findings.",
			clause:  noneWhere(leaf("payload.severity", "eq", "CRITICAL"), leaf("payload.status", "eq", "ACTIVE"), "critical finding {{.payload.id}} is active"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.no_high_findings_unaddressed", control: ctrlCC68, severity: core.SeverityHigh, category: catMonitoring, cadence: cadenceDaily,
			accepts: []string{etVulnerabilityFinding},
			desc:    "No HIGH vulnerability finding is active.",
			rem:     "Remediate or formally suppress all active HIGH findings.",
			clause:  noneWhere(leaf("payload.severity", "eq", "HIGH"), leaf("payload.status", "eq", "ACTIVE"), "high finding {{.payload.id}} is active"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.container_scan_on_push", control: ctrlCC68, severity: core.SeverityMedium, category: catMonitoring, cadence: cadenceDaily,
			accepts: []string{etContainerRegistry},
			desc:    "All container registries scan images on push.",
			rem:     "Enable scan-on-push on each container repository.",
			clause:  all(leaf("payload.scan_on_push_enabled", "eq", true), "registry {{.payload.name}} does not scan images on push"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.no_public_container_repos", control: ctrlCC68, severity: core.SeverityHigh, category: catDataProtection, cadence: cadenceDaily,
			accepts: []string{etContainerRegistry},
			desc:    "No container registry is publicly accessible.",
			rem:     "Make public container repositories private.",
			clause:  none(leaf("payload.is_public", "eq", true), "registry {{.payload.name}} is publicly accessible"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.8.macie_enabled", control: ctrlCC68, severity: core.SeverityMedium, category: catMonitoring, cadence: cadenceDaily,
			accepts: []string{etSecurityService},
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

// --- password-policy clauses ---------------------------------------
//
// All four read a password_policy record of either version. Every field
// they touch is optional in v2 (it had to be: an Entra record can answer
// expiry and nothing else, and v1's eight required fields are why no
// Entra record could be emitted at all), so every one of them guards its
// reads with is_set. That is not ceremony — the evaluator errors on a
// reference to a field the record does not carry, in a filter as much as
// in a condition, so an unguarded read would turn a partially-answering
// source into exit 3 for the whole run.
//
// Where a record cannot answer a clause's question at all, the clause
// filters it out of scope rather than failing it: "the source could not
// see this setting" is not "the setting is off", and inventing a fail
// paints a red with no remediation anywhere. When nothing in the slot can
// answer, the clause examined nothing and the engine reports it as
// vacuous (core.DiagVacuousClauses) instead of showing a green tick over
// an unexamined estate.

// passwordLengthClause builds "every password policy in force requires at
// least min characters", skipping policies whose platform does not expose
// a minimum length (Entra fixes it as a Microsoft constant with no tenant
// setting — and reading that constant out of documentation is not
// evidence). A configured 0 is a different thing entirely: it is an
// observed "no minimum", and it fails.
func passwordLengthClause(minLength int) core.PassWhenClause {
	return allWhere(isSet("payload.min_length"),
		leaf("payload.min_length", "gte", minLength),
		fmt.Sprintf("password policy {{.payload.id}} has a minimum length below %d", minLength))
}

// passwordExpiryClause builds "passwords expire within maxDays, or
// rotation is centrally managed". max_age_days 0 is the vendors' own
// encoding of "no expiry", which NIST 800-63B now treats as correct when
// rotation is event-driven, so it passes.
func passwordExpiryClause(maxDays int) core.PassWhenClause {
	return allWhere(isSet("payload.max_age_days"),
		anyOf(leaf("payload.max_age_days", "eq", 0), leaf("payload.max_age_days", "lte", maxDays)),
		fmt.Sprintf("password policy {{.payload.id}} expires passwords after more than %d days", maxDays))
}

// passwordReusePreventedClause builds "reuse is prevented".
//
// It used to read reuse_prevention_count >= 24. Not every vendor
// discloses a depth: Google's Cloud Identity API exposes allowReuse as a
// bare boolean and documents no history length at all, so "the last 24"
// is not a question it can be asked — the answer could be 1. The clause
// now asks what every source can answer truthfully, and the depth, where
// a vendor does disclose it, is still in the signed envelope for an
// auditor to read.
//
// The trade this accepts, stated plainly: an AWS account with history
// depth 1 now passes a clause that "the last 24" would have failed. The
// remedy for that is a SECOND clause on the depth, guarded by is_set so
// it judges only the sources that disclose one — deferred as its own
// decision, and deliberately not taken here by giving Google a different
// verdict instead.
func passwordReusePreventedClause() core.PassWhenClause {
	answerable := anyOf(isSet("payload.reuse_prevented"), isSet("payload.reuse_prevention_count"))
	prevented := anyOf(
		allOf(isSet("payload.reuse_prevented"), leaf("payload.reuse_prevented", "eq", true)),
		allOf(isSet("payload.reuse_prevention_count"), leaf("payload.reuse_prevention_count", "gte", 1)),
	)
	return allWhere(answerable, prevented,
		"password policy {{.payload.id}} does not prevent password reuse")
}

// passwordStrengthEnforcedClause builds "a password-strength control is
// enforced" — the reframed complexity check.
//
// It used to read "all four character classes are required", which is a
// question only a per-class vendor can be asked. Google reports
// allowedStrength as STRONG or WEAK and says in its own administrator
// documentation that a strong password "doesn't need to have a specific
// number of characters of a specific type": STRONG is entropy plus breach
// and common-password screening, explicitly not a character-class rule.
// So passing STRONG as "all four true" would fabricate a claim the vendor
// itself disclaims, while failing STRONG would paint a permanent red with
// no setting anywhere to turn on — against a provider following NIST
// 800-63B (which deprecates composition rules) rather than defying it.
// The clause was what was wrong, not the source.
//
// Each arm is therefore a true statement about what was observed:
//
//   - per_class — every character class is required. This is every v1
//     record and every AWS/Okta/AD v2 record, so those estates get exactly
//     the verdict they got before.
//   - strength_enum — the minimum rating the platform will accept is its
//     strongest.
//   - fixed — the platform enforces a strength rule the tenant cannot
//     configure or weaken, which is a property of the platform and true of
//     the tenant by construction (unlike a default, which the tenant may
//     have overridden and which must never be emitted).
//
// complexity_model "none" — an AWS account with no password policy at all
// — matches no arm and fails, which is the whole point of spelling "none"
// out rather than letting it be implied by absence.
//
// Every arm is_set-guards its fields before reading them: any_of keeps
// evaluating after a false, so an unguarded arm would error the policy on
// the very records the other arms exist to serve.
func passwordStrengthEnforcedClause() core.PassWhenClause {
	answerable := anyOf(isSet("payload.complexity_model"), isSet("payload.requires_uppercase"))
	perClass := allOf(
		isSet("payload.requires_uppercase"), isSet("payload.requires_lowercase"),
		isSet("payload.requires_numbers"), isSet("payload.requires_symbols"),
		leaf("payload.requires_uppercase", "eq", true),
		leaf("payload.requires_lowercase", "eq", true),
		leaf("payload.requires_numbers", "eq", true),
		leaf("payload.requires_symbols", "eq", true),
	)
	strengthEnum := allOf(
		isSet("payload.password_strength"),
		leaf("payload.password_strength", "eq", "strong"),
	)
	platformFixed := allOf(
		isSet("payload.complexity_model"),
		leaf("payload.complexity_model", "eq", "fixed"),
	)
	return allWhere(answerable, anyOf(perClass, strengthEnum, platformFixed),
		"password policy {{.payload.id}} enforces no password-strength requirement")
}

// cc6OrgGovernancePolicies — CC6.1/CC6.3 logical access governance at the
// source-control org level: org-wide MFA enforcement and least-privilege
// default member access. Consumes the singleton source_control_org_policy
// record (GitHub org, GitLab group, …).
func cc6OrgGovernancePolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc6.1.org_2fa_required", control: ctrlCC61, severity: core.SeverityHigh, category: catAccess, cadence: cadenceDaily,
			accepts: []string{"source_control_org_policy"},
			desc:    "The source-control organization enforces two-factor authentication for all members.",
			rem:     "Enable the org-wide two-factor authentication requirement.",
			clause:  all(leaf("payload.two_factor_required", "eq", true), "organization {{.payload.id}} does not require two-factor authentication"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc6.3.repo_default_permission_least_privilege", control: "CC6.3", severity: core.SeverityMedium, category: catAccess, cadence: cadenceDaily,
			accepts: []string{"source_control_org_policy"},
			desc:    "The source-control organization grants members a least-privilege default repository permission (none or read).",
			rem:     "Set the default member repository permission to `none` or `read`; grant write/admin per team.",
			clause:  all(leaf("payload.default_member_repository_permission", "not_in", []any{"write", "admin"}), "organization {{.payload.id}} grants an overly broad default repository permission"),
		}.policy(),
	}
}

// cc6RosterPolicies — CC6.2 user provisioning and removal, checked by
// joining accounts in every bound identity source to the roster the
// project designates (experimental.roster.source). The roster directory's
// own accounts are never checked against itself, so deprovisioning from
// that directory still needs the manual CC6.2 evidence.
func cc6RosterPolicies() []core.Policy {
	return []core.Policy{
		rosterPolicy{
			id: "soc2.cc6.2.accounts_linked_to_roster", control: ctrlCC62, severity: core.SeverityHigh,
			desc: "Every active human identity in the bound sources — an account (GitHub, GitLab, AWS IAM, …) or a cloud IAM role granted to a principal — belongs to a person in the designated roster directory, matched by email or a declared alias. " +
				"Accounts in the roster directory itself are not checked. A person deleted from the roster directory drops out of the roster, so their remaining accounts and grants are reported here.",
			rem: "Remove the account, or revoke the role grant, for identities that belong to no one in the roster. Link one whose email is absent or differs from the roster's with experimental.roster.aliases, and declare bots and deploy users in experimental.roster.non_human.",
			clause: allWhere(allOf(leaf("account.active", "eq", true), leaf("account.non_human", "eq", false)), inRoster(nil),
				"identity {{.account.ref}} is not linked to anyone in the roster"),
		}.policy(),
		rosterPolicy{
			id: "soc2.cc6.2.no_active_accounts_for_inactive_personnel", control: ctrlCC62, severity: core.SeverityCritical,
			desc: "No active account, and no cloud IAM role grant, in the bound sources belongs to a person the designated roster directory marks inactive (suspended, disabled or deprovisioned). " +
				"This does not attest removal from the roster directory itself (keep providing manual evidence for that), and people deleted outright from the roster are reported by soc2.cc6.2.accounts_linked_to_roster instead.",
			rem: "Disable or remove the accounts, and revoke the role grants, of people who are inactive in the roster, in every system where they still have access.",
			clause: noneWhere(leaf("account.active", "eq", true), inRoster(leaf("payload.status", "eq", "inactive")),
				"identity {{.account.ref}} belongs to {{.account.key}}, who is inactive in the roster"),
		}.policy(),
	}
}
