# METADATA
# title: PI1.4 - SNS Topic KMS Encryption
# description: SNS topics should use KMS encryption for message integrity
# scope: package
package sigcomply.soc2.pi1_4_sns_kms_encryption

metadata := {
	"id": "soc2-pi1.4-sns-kms-encryption",
	"name": "SNS Topic KMS Encryption",
	"framework": "soc2",
	"control": "PI1.4",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sns:topic"],
	"remediation": "Enable KMS encryption on the SNS topic.",
}

violations contains violation if {
	input.resource_type == "aws:sns:topic"
	input.data.kms_key_id == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SNS topic '%s' does not use KMS encryption", [input.data.name]),
		"details": {"topic_name": input.data.name},
	}
}
