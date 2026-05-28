package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// cc7Policies returns the CC7 system-operations automated policies:
// audit logging, log retention, configuration recording, security
// service enablement, CloudWatch metric alarms, and vulnerability
// posture.
func cc7Policies() []core.Policy {
	out := make([]core.Policy, 0, 24)
	out = append(out, cc7LoggingPolicies()...)
	out = append(out, cc7AlarmPolicies()...)
	out = append(out, cc7OperationsPolicies()...)
	return out
}

// cc7LoggingPolicies — CC7.1 monitoring, logging, and security services.
func cc7LoggingPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc7.1.audit_logging_enabled", control: "CC7.1", severity: core.SeverityHigh, category: "logging", cadence: "daily",
			accepts: []string{"audit_log_trail"},
			desc:    "Audit logging is enabled and covers all regions.",
			rem:     "Enable a multi-region audit log trail.",
			clause:  all(allOf(leaf("payload.is_enabled", "eq", true), leaf("payload.is_multi_region", "eq", true)), "audit trail {{.payload.name}} is not enabled across all regions"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.1.audit_log_integrity_enabled", control: "CC7.1", severity: core.SeverityMedium, category: "logging", cadence: "daily",
			accepts: []string{"audit_log_trail"},
			desc:    "Audit log file integrity validation is enabled.",
			rem:     "Enable log file validation on each audit trail.",
			clause:  all(leaf("payload.log_file_validation_enabled", "eq", true), "audit trail {{.payload.name}} does not have log file validation enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.1.audit_log_kms_encrypted", control: "CC7.1", severity: core.SeverityMedium, category: "logging", cadence: "daily",
			accepts: []string{"audit_log_trail"},
			desc:    "Audit logs are encrypted with a customer-managed key.",
			rem:     "Configure KMS encryption on each audit trail.",
			clause:  all(leaf("payload.kms_encrypted", "eq", true), "audit trail {{.payload.name}} is not KMS-encrypted"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.1.log_retention_min_90d", control: "CC7.1", severity: core.SeverityMedium, category: "logging", cadence: "daily",
			accepts: []string{"log_group"},
			desc:    "All log groups retain logs for at least 90 days.",
			rem:     "Set retention to 90 days or more on each log group.",
			clause:  all(allOf(leaf("payload.retention_set", "eq", true), leaf("payload.retention_days", "gte", 90)), "log group {{.payload.name}} retains logs for fewer than 90 days"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.1.config_recording_enabled", control: "CC7.1", severity: core.SeverityHigh, category: "monitoring", cadence: "daily",
			accepts: []string{"configuration_recorder"},
			desc:    "Configuration change recording is enabled.",
			rem:     "Enable a configuration recorder (AWS Config or equivalent).",
			clause:  all(leaf("payload.is_recording", "eq", true), "configuration recorder {{.payload.name}} is not recording"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.1.config_all_resource_types", control: "CC7.1", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"configuration_recorder"},
			desc:    "Configuration recording covers all resource types.",
			rem:     "Configure the recorder to capture all supported resource types.",
			clause:  all(leaf("payload.all_resource_types", "eq", true), "configuration recorder {{.payload.name}} does not record all resource types"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.1.securityhub_enabled", control: "CC7.1", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"security_service"},
			desc:    "A SIEM / security aggregation service is enabled.",
			rem:     "Enable SecurityHub (or an equivalent SIEM) on the account.",
			clause:  anyWhere(leaf("payload.service_type", "eq", "siem"), leaf("payload.is_enabled", "eq", true), "no SIEM service is enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.1.inspector_enabled", control: "CC7.1", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"security_service"},
			desc:    "A vulnerability scanning service is enabled.",
			rem:     "Enable Inspector (or an equivalent scanner) on the account.",
			clause:  anyWhere(leaf("payload.service_type", "eq", "vulnerability_scanner"), leaf("payload.is_enabled", "eq", true), "no vulnerability scanner is enabled"),
		}.policy(),
	}
}

// cc7OperationsPolicies — CC7.2/7.3/7.4/7.5 operational posture.
func cc7OperationsPolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "soc2.cc7.2.threat_detection_all_regions", control: "CC7.2", severity: core.SeverityHigh, category: "monitoring", cadence: "daily",
			accepts: []string{"threat_detection_service"},
			desc:    "Threat detection is active in every region.",
			rem:     "Enable the threat detection service in all regions.",
			clause:  all(leaf("payload.is_enabled", "eq", true), "threat detection service {{.payload.name}} is not enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.3.compute_monitoring_enabled", control: "CC7.3", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"compute_instance"},
			desc:    "All compute instances have detailed monitoring enabled.",
			rem:     "Enable detailed monitoring on each compute instance.",
			clause:  all(leaf("payload.monitoring_enabled", "eq", true), "instance {{.payload.name}} does not have monitoring enabled"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.4.no_critical_vulns_active", control: "CC7.4", severity: core.SeverityCritical, category: "monitoring", cadence: "daily",
			accepts: []string{"vulnerability_finding"},
			desc:    "No CRITICAL vulnerability remains active.",
			rem:     "Remediate or suppress all active CRITICAL vulnerabilities.",
			clause:  noneWhere(allOf(leaf("payload.severity", "eq", "CRITICAL"), leaf("payload.status", "eq", "ACTIVE")), leaf("id", "is_set", nil), "critical vulnerability {{.payload.id}} is active"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.5.database_multi_az", control: "CC7.5", severity: core.SeverityMedium, category: "availability", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "All managed databases are deployed across multiple availability zones.",
			rem:     "Enable multi-AZ / regional high availability on each database.",
			clause:  all(leaf("payload.multi_az", "eq", true), "database {{.payload.name}} is not multi-AZ"),
		}.policy(),
		autoPolicy{
			id: "soc2.cc7.5.database_deletion_protection", control: "CC7.5", severity: core.SeverityMedium, category: "availability", cadence: "daily",
			accepts: []string{"managed_database_instance"},
			desc:    "All managed databases have deletion protection enabled.",
			rem:     "Enable deletion protection on each database.",
			clause:  all(leaf("payload.deletion_protection", "eq", true), "database {{.payload.name}} does not have deletion protection"),
		}.policy(),
	}
}

// cc7AlarmPolicies — CC7.2 CloudWatch metric-filter alarms. These use
// the rule: escape hatch because matching requires substring search over
// the metric filter pattern, which the pass_when DSL cannot express.
func cc7AlarmPolicies() []core.Policy {
	mk := func(id, desc string, ruleRef string) core.Policy {
		return rulePolicy{
			id: id, control: "CC7.2", severity: core.SeverityMedium, category: "monitoring", cadence: "daily",
			accepts: []string{"cloudwatch_alarm"},
			desc:    desc,
			rem:     "Create the CloudWatch metric filter and alarm covering this event class.",
			ruleRef: ruleRef,
		}.policy()
	}
	return []core.Policy{
		mk("soc2.cc7.2.alarm_unauthorized_api_calls", "A metric alarm exists for unauthorized API calls.", ruleAlarmUnauthorized),
		mk("soc2.cc7.2.alarm_root_account_usage", "A metric alarm exists for root account usage.", ruleAlarmRootUsage),
		mk("soc2.cc7.2.alarm_iam_policy_changes", "A metric alarm exists for IAM policy changes.", ruleAlarmIAMChanges),
		mk("soc2.cc7.2.alarm_cloudtrail_config_changes", "A metric alarm exists for audit log configuration changes.", ruleAlarmTrailChanges),
		mk("soc2.cc7.2.alarm_console_login_no_mfa", "A metric alarm exists for console sign-ins without MFA.", ruleAlarmConsoleNoMFA),
		mk("soc2.cc7.2.alarm_security_group_changes", "A metric alarm exists for security group changes.", ruleAlarmSGChanges),
		mk("soc2.cc7.2.alarm_vpc_changes", "A metric alarm exists for VPC changes.", ruleAlarmVPCChanges),
		mk("soc2.cc7.2.alarm_kms_key_deletion", "A metric alarm exists for KMS key disable/deletion.", ruleAlarmKMSDeletion),
	}
}
