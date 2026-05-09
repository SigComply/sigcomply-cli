# METADATA
# title: CC6.2 - SNS Topic Encryption
# description: SNS topics should be encrypted with KMS for data protection
# scope: package
package sigcomply.soc2.cc6_2_sns_encryption

metadata := {
	"id": "soc2-cc6.2-sns-encryption",
	"name": "SNS Topic Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sns:topic"],
	"remediation": "Enable server-side encryption with KMS for the SNS topic.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:sns:topic"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SNS topic '%s' is not encrypted with KMS", [input.data.name]),
		"details": {
			"topic_name": input.data.name,
		},
	}
}
