# METADATA
# title: CC6.2 - SQS Queue Encryption
# description: SQS queues should be encrypted with KMS or SQS-managed encryption
# scope: package
package sigcomply.soc2.cc6_2_sqs_encryption

metadata := {
	"id": "soc2-cc6.2-sqs-encryption",
	"name": "SQS Queue Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sqs:queue"],
	"remediation": "Enable server-side encryption for the SQS queue using KMS or SQS-managed encryption.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:sqs:queue"
	input.data.sse_enabled == false
	input.data.sqs_managed_encryption == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SQS queue '%s' does not have encryption enabled", [input.data.name]),
		"details": {
			"queue_name": input.data.name,
		},
	}
}
