# METADATA
# title: CC6.8 - Lambda VPC Configuration
# description: Lambda functions should be configured to run within a VPC for network isolation
# scope: package
package sigcomply.soc2.cc6_8_lambda_vpc

metadata := {
	"id": "soc2-cc6.8-lambda-vpc",
	"name": "Lambda VPC Configuration",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:lambda:function"],
	"remediation": "Configure the Lambda function to run within a VPC by specifying subnet IDs and security groups.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.vpc_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' is not configured to run within a VPC", [input.data.name]),
		"details": {
			"function_name": input.data.name,
		},
	}
}
