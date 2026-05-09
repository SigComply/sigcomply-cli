# METADATA
# title: CC6.6 - SQS Queue No Public Access
# description: SQS queue policies must not allow public access
# scope: package
package sigcomply.soc2.cc6_6_sqs_public_access

metadata := {
	"id": "soc2-cc6.6-sqs-public-access",
	"name": "SQS Queue No Public Access",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sqs:queue"],
	"remediation": "Update the SQS queue policy to remove wildcard principal (*) access. Restrict to specific AWS accounts or IAM roles.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:sqs:queue"
	input.data.policy_public_access == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SQS queue '%s' has a policy that allows public access", [input.data.queue_name]),
		"details": {
			"queue_name": input.data.queue_name,
			"queue_url": input.data.queue_url,
		},
	}
}
