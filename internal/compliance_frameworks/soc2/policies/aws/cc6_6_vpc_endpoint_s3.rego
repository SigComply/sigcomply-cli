# METADATA
# title: CC6.6 - VPC Endpoint for S3
# description: VPC should have an S3 endpoint to keep traffic within the AWS network
# scope: package
package sigcomply.soc2.cc6_6_vpc_endpoint_s3

metadata := {
	"id": "soc2-cc6.6-vpc-endpoint-s3",
	"name": "VPC Endpoint for S3",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:vpc-endpoint-status"],
	"remediation": "Create a VPC endpoint for S3 to keep traffic within the AWS network.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:vpc-endpoint-status"
	input.data.has_s3_endpoint == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No VPC endpoint for S3 found in this region",
		"details": {
			"region": input.data.region,
		},
	}
}
