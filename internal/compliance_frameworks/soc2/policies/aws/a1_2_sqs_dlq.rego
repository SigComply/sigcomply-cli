# METADATA
# title: A1.2 - SQS Dead Letter Queue
# description: SQS queues should have a dead letter queue configured
# scope: package
package sigcomply.soc2.a1_2_sqs_dlq

metadata := {
	"id": "soc2-a1.2-sqs-dlq",
	"name": "SQS Dead Letter Queue",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sqs:queue"],
	"remediation": "Configure a dead letter queue (redrive policy) for the SQS queue.",
}

violations contains violation if {
	input.resource_type == "aws:sqs:queue"
	input.data.has_dlq == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SQS queue '%s' does not have a dead letter queue configured", [input.data.name]),
		"details": {"queue_name": input.data.name},
	}
}
