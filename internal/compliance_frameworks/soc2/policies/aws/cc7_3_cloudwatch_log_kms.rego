# METADATA
# title: CC7.3 - CloudWatch Log Group Encryption
# description: CloudWatch Log Groups should use KMS encryption to protect security event logs
# scope: package
package sigcomply.soc2.cc7_3_cloudwatch_log_kms

metadata := {
	"id": "soc2-cc7.3-cloudwatch-log-kms",
	"name": "CloudWatch Log Group Encryption",
	"framework": "soc2",
	"control": "CC7.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:logs:log-group"],
	"remediation": "Associate a KMS key with the CloudWatch Log Group for encryption.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:logs:log-group"
	input.data.kms_key_id == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudWatch Log Group '%s' does not use KMS encryption for security event logs", [input.data.name]),
		"details": {"log_group_name": input.data.name},
	}
}
