package iso27001

import "github.com/sigcomply/sigcomply-cli/internal/core"

// directoryUserTypes is the substitutability set for identity policies.
var directoryUserTypes = []string{"directory_user", "directory_user.v2"}

// technologicalPolicies returns the Theme D (8.x) automated control
// policies. ISO 27001 reuses the same evidence types as SOC 2 with
// ISO-specific thresholds (e.g. 365-day log retention vs SOC 2's 90).
func technologicalPolicies() []core.Policy {
	out := make([]core.Policy, 0, 48)
	out = append(out, techAccessPolicies()...)
	out = append(out, techCryptoPolicies()...)
	out = append(out, techLoggingPolicies()...)
	out = append(out, techNetworkPolicies()...)
	out = append(out, techDevSecOpsPolicies()...)
	return out
}

func techAccessPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "iso27001.8.2.privileged_mfa_enforced", control: "A.8.2", severity: core.SeverityCritical, category: "access", cadence: "daily",
			accepts: []string{"directory_user.v2"},
			desc:    "Privileged users have MFA enabled.",
			rem:     "Enable MFA for all admin users.",
			clause:  allWhere(leaf("payload.is_admin", "eq", true), leaf("payload.mfa_enabled", "eq", true), "admin user {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.3.storage_no_public_access", control: "A.8.3", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"object_storage_bucket"},
			desc:    "Object storage buckets block public access.",
			rem:     "Block public access on each bucket.",
			clause:  all(leaf("payload.public_access_blocked", "eq", true), "bucket {{.payload.name}} does not block public access"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.3.database_no_public_access", control: "A.8.3", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "Managed databases are not publicly accessible.",
			rem:     "Disable public accessibility on each database.",
			clause:  all(leaf("payload.publicly_accessible", "eq", false), "database {{.payload.name}} is publicly accessible"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.3.no_broad_admin_iam_bindings", control: "A.8.3", severity: core.SeverityHigh, category: "access", cadence: "daily",
			accepts: []string{"iam_binding"},
			desc:    "No individual user holds an unconditional broad-admin role.",
			rem:     "Grant admin roles to groups with conditions, not directly to users.",
			clause:  noneWhere(leaf("payload.principal_type", "eq", "user"), allOf(leaf("payload.is_broad_admin_role", "eq", true), leaf("payload.has_condition", "eq", false)), "user {{.payload.principal_id}} holds unconditional broad-admin role {{.payload.role}}"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.4.branch_protection_enabled", control: "A.8.4", severity: core.SeverityHigh, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "Repositories protect their default branch.",
			rem:     "Enable branch protection on each repository.",
			clause:  all(leaf("payload.default_branch_protected", "eq", true), "repository {{.payload.name}} does not protect its default branch"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.4.required_code_reviews", control: "A.8.4", severity: core.SeverityHigh, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "Repositories require code review.",
			rem:     "Require at least one reviewer on each repository.",
			clause:  all(leaf("payload.required_reviewers_count", "gte", 1), "repository {{.payload.name}} does not require code review"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.5.mfa_enforced_all_users", control: "A.8.5", severity: core.SeverityCritical, category: "access", cadence: "daily",
			accepts: directoryUserTypes,
			desc:    "All users have MFA enabled (secure authentication).",
			rem:     "Enable MFA for every user.",
			clause:  all(leaf("payload.mfa_enabled", "eq", true), "user {{.payload.display_name}} does not have MFA enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.5.password_minimum_length", control: "A.8.5", severity: core.SeverityMedium, category: "access", cadence: "daily",
			accepts: []string{"password_policy"},
			desc:    "The password policy requires at least 12 characters.",
			rem:     "Set minimum password length to 12 or greater.",
			clause:  all(leaf("payload.min_length", "gte", 12), "password policy minimum length is below 12"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.5.password_complexity", control: "A.8.5", severity: core.SeverityMedium, category: "access", cadence: "daily",
			accepts: []string{"password_policy"},
			desc:    "The password policy requires all four character classes.",
			rem:     "Enable uppercase, lowercase, number, and symbol requirements.",
			clause: all(allOf(
				leaf("payload.requires_uppercase", "eq", true),
				leaf("payload.requires_lowercase", "eq", true),
				leaf("payload.requires_numbers", "eq", true),
				leaf("payload.requires_symbols", "eq", true),
			), "password policy does not require all four character classes"),
		}.policy(),
	}
}

func techCryptoPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "iso27001.8.24.storage_encryption_at_rest", control: "A.8.24", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"object_storage_bucket"},
			desc:    "Object storage is encrypted at rest.",
			rem:     "Enable encryption at rest on each bucket.",
			clause:  all(leaf("payload.encryption_at_rest_enabled", "eq", true), "bucket {{.payload.name}} is not encrypted at rest"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.24.database_encryption_at_rest", control: "A.8.24", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "Managed databases are encrypted at rest.",
			rem:     "Encrypt each database at rest.",
			clause:  all(leaf("payload.storage_encrypted", "eq", true), "database {{.payload.name}} is not encrypted at rest"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.24.compute_disk_encrypted", control: "A.8.24", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"compute_instance"},
			desc:    "Compute instances have encrypted disks.",
			rem:     "Encrypt the root volume of each instance.",
			clause:  all(leaf("payload.root_volume_encrypted", "eq", true), "instance {{.payload.name}} has an unencrypted disk"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.24.kms_key_rotation", control: "A.8.24", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"kms_key"},
			desc:    "Customer-managed KMS keys rotate automatically.",
			rem:     "Enable rotation on each customer-managed key.",
			clause:  allWhere(leaf("payload.is_customer_managed", "eq", true), leaf("payload.rotation_enabled", "eq", true), "KMS key {{.payload.key_id}} does not have rotation enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.24.secrets_rotation_enabled", control: "A.8.24", severity: core.SeverityMedium, category: "data-protection", cadence: "daily",
			accepts: []string{"secret"},
			desc:    "Managed secrets rotate automatically.",
			rem:     "Enable rotation on each secret.",
			clause:  all(leaf("payload.rotation_enabled", "eq", true), "secret {{.payload.name}} does not have rotation enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.21.tls_certificates_valid", control: "A.8.21", severity: core.SeverityMedium, category: "data-protection", cadence: "daily",
			accepts: []string{"tls_certificate"},
			desc:    "No TLS certificate expires within 30 days.",
			rem:     "Renew certificates expiring within 30 days.",
			clause:  all(leaf("payload.days_until_expiry", "gte", 30), "certificate {{.payload.domain}} expires within 30 days"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.21.tls_auto_renew_enabled", control: "A.8.21", severity: core.SeverityLow, category: "data-protection", cadence: "daily",
			accepts: []string{"tls_certificate"},
			desc:    "Managed TLS certificates auto-renew.",
			rem:     "Enable auto-renewal on each managed certificate.",
			// Scope to managed certs: imported certs omit auto_renew.
			clause: allWhere(leaf("payload.is_managed", "eq", true), leaf("payload.auto_renew", "eq", true), "certificate {{.payload.domain}} does not auto-renew"),
		}.policy(),
	}
}

func techLoggingPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "iso27001.8.15.audit_logging_enabled", control: "A.8.15", severity: core.SeverityHigh, category: "logging", cadence: "daily",
			accepts: []string{"audit_log_trail"},
			desc:    "Audit logging is enabled across all regions.",
			rem:     "Enable a multi-region audit trail.",
			clause:  all(allOf(leaf("payload.is_enabled", "eq", true), leaf("payload.is_multi_region", "eq", true)), "audit trail {{.payload.name}} is not enabled across all regions"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.15.audit_log_integrity", control: "A.8.15", severity: core.SeverityMedium, category: "logging", cadence: "daily",
			accepts: []string{"audit_log_trail"},
			desc:    "Audit log integrity validation is enabled.",
			rem:     "Enable log file validation on each trail.",
			clause:  all(leaf("payload.log_file_validation_enabled", "eq", true), "audit trail {{.payload.name}} does not validate log integrity"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.15.audit_log_encrypted", control: "A.8.15", severity: core.SeverityMedium, category: "logging", cadence: "daily",
			accepts: []string{"audit_log_trail"},
			desc:    "Audit logs are encrypted.",
			rem:     "Enable KMS encryption on each trail.",
			clause:  all(leaf("payload.kms_encrypted", "eq", true), "audit trail {{.payload.name}} is not encrypted"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.15.log_retention_min_365d", control: "A.8.15", severity: core.SeverityMedium, category: "logging", cadence: "daily",
			accepts: []string{"log_group"},
			desc:    "Log groups retain logs for at least 365 days (ISO 27001 baseline).",
			rem:     "Set retention to 365 days or more on each log group.",
			clause:  all(allOf(leaf("payload.retention_set", "eq", true), leaf("payload.retention_days", "gte", 365)), "log group {{.payload.name}} retains logs for fewer than 365 days"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.9.config_recording_enabled", control: "A.8.9", severity: core.SeverityHigh, category: "monitoring", cadence: "daily",
			accepts: []string{"config_change_tracking"},
			desc:    "Configuration change recording is enabled.",
			rem:     "Enable a configuration recorder.",
			clause:  all(leaf("payload.is_recording", "eq", true), "configuration recorder {{.payload.name}} is not recording"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.9.config_all_resources", control: "A.8.9", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"config_change_tracking"},
			desc:    "Configuration recording covers all resource types.",
			rem:     "Record all supported resource types.",
			clause:  all(leaf("payload.all_resource_types", "eq", true), "configuration recorder {{.payload.name}} does not record all resource types"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.16.threat_detection_active", control: "A.8.16", severity: core.SeverityHigh, category: "monitoring", cadence: "daily",
			accepts: []string{"threat_detection_service"},
			desc:    "Threat detection is active.",
			rem:     "Enable the threat detection service.",
			clause:  all(leaf("payload.is_enabled", "eq", true), "threat detection service {{.payload.name}} is not enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.16.compute_monitoring_enabled", control: "A.8.16", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"compute_instance"},
			desc:    "Compute instances have monitoring enabled.",
			rem:     "Enable detailed monitoring on each instance.",
			clause:  all(leaf("payload.monitoring_enabled", "eq", true), "instance {{.payload.name}} does not have monitoring enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.16.security_aggregation_enabled", control: "A.8.16", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"security_service"},
			desc:    "A SIEM / security aggregation service is enabled.",
			rem:     "Enable a SIEM service on the account.",
			clause:  anyWhere(leaf("payload.service_type", "eq", "siem"), leaf("payload.is_enabled", "eq", true), "no SIEM service is enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.7.threat_detection_enabled", control: "A.8.7", severity: core.SeverityHigh, category: "monitoring", cadence: "daily",
			accepts: []string{"threat_detection_service"},
			desc:    "Malware / threat detection is enabled.",
			rem:     "Enable the threat detection service.",
			clause:  all(leaf("payload.is_enabled", "eq", true), "threat detection service {{.payload.name}} is not enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.7.no_critical_malware_findings", control: "A.8.7", severity: core.SeverityCritical, category: "monitoring", cadence: "daily",
			accepts: []string{"vulnerability_finding"},
			desc:    "No CRITICAL malware finding is active.",
			rem:     "Remediate active CRITICAL findings.",
			clause:  noneWhere(leaf("payload.severity", "eq", "CRITICAL"), leaf("payload.status", "eq", "ACTIVE"), "critical finding {{.payload.id}} is active"),
		}.policy(),
	}
}

func techNetworkPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "iso27001.8.20.no_unrestricted_ssh", control: "A.8.20", severity: core.SeverityHigh, category: "network", cadence: "daily",
			accepts: []string{"firewall_rule"},
			desc:    "SSH (port 22) is not exposed to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 22.",
			clause:  unrestrictedPortClause(22),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.20.no_unrestricted_rdp", control: "A.8.20", severity: core.SeverityHigh, category: "network", cadence: "daily",
			accepts: []string{"firewall_rule"},
			desc:    "RDP (port 3389) is not exposed to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening port 3389.",
			clause:  unrestrictedPortClause(3389),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.20.no_unrestricted_database_ports", control: "A.8.20", severity: core.SeverityHigh, category: "network", cadence: "daily",
			accepts: []string{"firewall_rule"},
			desc:    "Database ports (3306, 5432, 1433) are not exposed to the public internet.",
			rem:     "Restrict the source CIDR of any rule opening a database port.",
			clause:  unrestrictedPortsClause(3306, 5432, 1433),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.20.vpc_flow_logs_enabled", control: "A.8.20", severity: core.SeverityMedium, category: "network", cadence: "daily",
			accepts: []string{"network"},
			desc:    "Virtual networks have flow logs enabled.",
			rem:     "Enable flow logs on each network.",
			clause:  all(leaf("payload.flow_logs_enabled", "eq", true), "network {{.payload.name}} does not have flow logs enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.12.storage_no_public_access", control: "A.8.12", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"object_storage_bucket"},
			desc:    "Object storage blocks public access (data leakage prevention).",
			rem:     "Block public access on each bucket.",
			clause:  all(leaf("payload.public_access_blocked", "eq", true), "bucket {{.payload.name}} does not block public access"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.12.database_no_public_access", control: "A.8.12", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "Databases are not publicly accessible (data leakage prevention).",
			rem:     "Disable public accessibility on each database.",
			clause:  all(leaf("payload.publicly_accessible", "eq", false), "database {{.payload.name}} is publicly accessible"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.12.no_public_container_repos", control: "A.8.12", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"container_registry"},
			desc:    "No container registry is publicly accessible.",
			rem:     "Make public container repositories private.",
			clause:  none(leaf("payload.is_public", "eq", true), "registry {{.payload.name}} is publicly accessible"),
		}.policy(),
	}
}

func techDevSecOpsPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "iso27001.8.8.container_scan_on_push", control: "A.8.8", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"container_registry"},
			desc:    "Container registries scan images on push (technical vulnerability management).",
			rem:     "Enable scan-on-push on each registry.",
			clause:  all(leaf("payload.scan_on_push_enabled", "eq", true), "registry {{.payload.name}} does not scan on push"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.8.no_critical_vulnerabilities", control: "A.8.8", severity: core.SeverityCritical, category: "monitoring", cadence: "daily",
			accepts: []string{"vulnerability_finding"},
			desc:    "No CRITICAL vulnerability is active.",
			rem:     "Remediate active CRITICAL vulnerabilities.",
			clause:  noneWhere(leaf("payload.severity", "eq", "CRITICAL"), leaf("payload.status", "eq", "ACTIVE"), "critical vulnerability {{.payload.id}} is active"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.13.database_backup_enabled", control: "A.8.13", severity: core.SeverityHigh, category: "availability", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "Managed databases have automated backups (information backup).",
			rem:     "Enable automated backups on each database.",
			clause:  all(leaf("payload.backup_enabled", "eq", true), "database {{.payload.name}} does not have backups enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.13.database_multi_az", control: "A.8.13", severity: core.SeverityMedium, category: "availability", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "Managed databases are multi-AZ.",
			rem:     "Enable multi-AZ deployment on each database.",
			clause:  all(leaf("payload.multi_az", "eq", true), "database {{.payload.name}} is not multi-AZ"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.13.storage_versioning_enabled", control: "A.8.13", severity: core.SeverityLow, category: "availability", cadence: "daily",
			accepts: []string{"object_storage_bucket"},
			desc:    "Object storage has versioning enabled.",
			rem:     "Enable versioning on each bucket.",
			clause:  all(leaf("payload.versioning_enabled", "eq", true), "bucket {{.payload.name}} does not have versioning enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.14.nosql_table_pitr_enabled", control: "A.8.14", severity: core.SeverityMedium, category: "availability", cadence: "daily",
			accepts: []string{"nosql_table"},
			desc:    "NoSQL tables have point-in-time recovery (redundancy).",
			rem:     "Enable point-in-time recovery on each NoSQL table.",
			clause:  all(leaf("payload.point_in_time_recovery_enabled", "eq", true), "table {{.payload.name}} does not have point-in-time recovery"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.25.branch_protection", control: "A.8.25", severity: core.SeverityHigh, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "Repositories protect their default branch (secure development).",
			rem:     "Enable branch protection on each repository.",
			clause:  all(leaf("payload.default_branch_protected", "eq", true), "repository {{.payload.name}} does not protect its default branch"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.25.no_force_push_to_main", control: "A.8.25", severity: core.SeverityMedium, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "Repositories disallow force-push to the default branch.",
			rem:     "Disable force-push on each repository.",
			clause:  none(leaf("payload.allows_force_push", "eq", true), "repository {{.payload.name}} allows force-push"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.25.secret_scanning_enabled", control: "A.8.25", severity: core.SeverityHigh, category: "data-protection", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "Repositories have secret scanning enabled.",
			rem:     "Enable secret scanning on each repository.",
			clause:  all(leaf("payload.secret_scanning_enabled", "eq", true), "repository {{.payload.name}} does not have secret scanning enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.28.code_scanning_enabled", control: "A.8.28", severity: core.SeverityMedium, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "Repositories have code scanning enabled (secure coding).",
			rem:     "Enable code scanning on each repository.",
			clause:  all(leaf("payload.code_scanning_enabled", "eq", true), "repository {{.payload.name}} does not have code scanning enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.28.dependabot_alerts_enabled", control: "A.8.28", severity: core.SeverityMedium, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "Repositories have dependency vulnerability alerts enabled.",
			rem:     "Enable dependency alerts on each repository.",
			clause:  all(leaf("payload.dependabot_alerts_enabled", "eq", true), "repository {{.payload.name}} does not have dependency alerts enabled"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.32.required_code_reviews", control: "A.8.32", severity: core.SeverityHigh, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "Repositories require code review (change management).",
			rem:     "Require at least one reviewer on each repository.",
			clause:  all(leaf("payload.required_reviewers_count", "gte", 1), "repository {{.payload.name}} does not require code review"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.32.no_force_push", control: "A.8.32", severity: core.SeverityMedium, category: "change-management", cadence: "daily",
			accepts: []string{"git_repository"},
			desc:    "Repositories disallow force-push (change management).",
			rem:     "Disable force-push on each repository.",
			clause:  none(leaf("payload.allows_force_push", "eq", true), "repository {{.payload.name}} allows force-push"),
		}.policy(),
	}
}
