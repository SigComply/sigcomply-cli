# METADATA
# title: CC7.1 - Lambda X-Ray Tracing
# description: Lambda functions should have X-Ray active tracing enabled
# scope: package
package sigcomply.soc2.cc7_1_lambda_xray_tracing

metadata := {
	"id": "soc2-cc7.1-lambda-xray-tracing",
	"name": "Lambda X-Ray Tracing",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:lambda:function"],
	"remediation": "Enable X-Ray active tracing for the Lambda function.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.tracing_mode != "Active"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' does not have X-Ray active tracing enabled", [input.data.name]),
		"details": {"function_name": input.data.name, "tracing_mode": input.data.tracing_mode},
	}
}
