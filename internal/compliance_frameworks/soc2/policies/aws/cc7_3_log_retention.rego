# METADATA
# title: CC7.3 - CloudWatch Log Retention Policy
# description: CloudWatch Log Groups should have a retention policy set for security event retention
# scope: package
package sigcomply.soc2.cc7_3_log_retention

metadata := {
	"id": "soc2-cc7.3-log-retention",
	"name": "CloudWatch Log Retention Policy",
	"framework": "soc2",
	"control": "CC7.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:logs:log-group"],
	"remediation": "Set a retention policy on the CloudWatch Log Group to ensure security event logs are retained.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:logs:log-group"
	input.data.has_retention == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudWatch Log Group '%s' does not have a retention policy set", [input.data.name]),
		"details": {"log_group_name": input.data.name},
	}
}
