# METADATA
# title: CC8.1 - Lambda Code Signing
# description: Lambda functions must have code signing enabled
# scope: package
package sigcomply.soc2.cc8_1_lambda_code_signing

metadata := {
	"id": "soc2-cc8.1-lambda-code-signing",
	"name": "Lambda Code Signing",
	"framework": "soc2",
	"control": "CC8.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:lambda:function"],
	"remediation": "Configure a code signing configuration for the Lambda function to ensure only trusted code is deployed",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.code_signing_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' does not have code signing enabled", [input.data.name]),
		"details": {
			"function_name": input.data.name,
		},
	}
}
