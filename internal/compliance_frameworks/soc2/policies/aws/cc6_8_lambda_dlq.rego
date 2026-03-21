# METADATA
# title: CC6.8 - Lambda Dead Letter Queue
# description: Lambda functions should have a dead letter queue configured for failed invocations
# scope: package
package sigcomply.soc2.cc6_8_lambda_dlq

metadata := {
	"id": "soc2-cc6.8-lambda-dlq",
	"name": "Lambda Dead Letter Queue",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:lambda:function"],
	"remediation": "Configure a dead letter queue (SQS or SNS) for the Lambda function to capture failed invocations.",
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.has_dlq == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' does not have a dead letter queue configured", [input.data.name]),
		"details": {
			"function_name": input.data.name,
		},
	}
}
