# METADATA
# title: CC6.2 - CloudWatch Log Group Encryption
# description: CloudWatch log groups should be encrypted with a KMS key
# scope: package
package sigcomply.soc2.cc6_2_cloudwatch_log_encryption

metadata := {
	"id": "soc2-cc6.2-cloudwatch-log-encryption",
	"name": "CloudWatch Log Group Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:logs:log-group"],
	"remediation": "Associate a KMS key with the CloudWatch log group using the AWS Console or CLI to encrypt log data at rest.",
}

violations contains violation if {
	input.resource_type == "aws:logs:log-group"
	input.data.kms_key_id == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudWatch log group '%s' is not encrypted with a KMS key", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
