# METADATA
# title: A1.2 - Lambda Multi-AZ VPC Deployment
# description: VPC-attached Lambda functions should span multiple availability zones
# scope: package
package sigcomply.soc2.a1_2_lambda_multi_az

metadata := {
	"id": "soc2-a1.2-lambda-multi-az",
	"name": "Lambda Multi-AZ VPC Deployment",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:lambda:function"],
	"remediation": "Configure the Lambda function's VPC settings to include subnets across multiple availability zones for high availability.",
}

violations contains violation if {
	input.resource_type == "aws:lambda:function"
	input.data.vpc_configured == true
	input.data.availability_zone_count < 2
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Lambda function '%s' is VPC-attached but only spans %d availability zone(s)", [input.data.function_name, input.data.availability_zone_count]),
		"details": {
			"function_name": input.data.function_name,
			"availability_zone_count": input.data.availability_zone_count,
		},
	}
}
