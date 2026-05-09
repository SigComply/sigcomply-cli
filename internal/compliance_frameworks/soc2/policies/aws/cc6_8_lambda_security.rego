# METADATA
# title: CC6.8 - Lambda Function Security
# description: Lambda functions must not use deprecated runtimes or be publicly accessible
# scope: package
package sigcomply.soc2.cc6_8_lambda_security

metadata := {
	"id": "soc2-cc6.8-lambda-security",
	"name": "Lambda Function Security",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:lambda:function"],
	"remediation": "Update Lambda runtime and restrict resource policy",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.runtime_deprecated == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' uses deprecated runtime '%s'", [input.data.name, input.data.runtime]),
		"details": {"name": input.data.name, "runtime": input.data.runtime},
	}
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.publicly_accessible == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' is publicly accessible", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
