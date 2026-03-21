# METADATA
# title: PI1.4 - CloudWatch Log Group KMS Encryption
# description: CloudWatch Log Groups should use KMS encryption for data integrity
# scope: package
package sigcomply.soc2.pi1_4_cloudwatch_log_kms

metadata := {
	"id": "soc2-pi1.4-cloudwatch-log-kms",
	"name": "CloudWatch Log Group KMS Encryption",
	"framework": "soc2",
	"control": "PI1.4",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:logs:log-group"],
	"remediation": "Associate a KMS key with the CloudWatch Log Group.",
}

violations contains violation if {
	input.resource_type == "aws:logs:log-group"
	input.data.kms_key_id == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudWatch Log Group '%s' does not use KMS encryption", [input.data.name]),
		"details": {"log_group_name": input.data.name},
	}
}
