# METADATA
# title: CC6.8 - Lambda Concurrency Limit
# description: Lambda functions should have reserved concurrency configured
# scope: package
package sigcomply.soc2.cc6_8_lambda_concurrency_limit

metadata := {
	"id": "soc2-cc6.8-lambda-concurrency-limit",
	"name": "Lambda Concurrency Limit",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:lambda:function"],
	"remediation": "Configure reserved concurrency for the Lambda function to prevent resource exhaustion",
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.reserved_concurrency < 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' does not have reserved concurrency configured", [input.data.name]),
		"details": {
			"function_name": input.data.name,
		},
	}
}
