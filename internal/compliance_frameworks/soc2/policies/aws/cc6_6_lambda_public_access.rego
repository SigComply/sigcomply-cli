# METADATA
# title: CC6.6 - Lambda Public Access
# description: Lambda functions should not be publicly accessible
# scope: package
package sigcomply.soc2.cc6_6_lambda_public_access

metadata := {
	"id": "soc2-cc6.6-lambda-public-access",
	"name": "Lambda Public Access",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:lambda:function"],
	"remediation": "Remove public access from the Lambda function's resource-based policy. Restrict invocation to specific AWS accounts, services, or IAM principals.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.publicly_accessible == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' is publicly accessible", [input.data.function_name]),
		"details": {"function_name": input.data.function_name},
	}
}
