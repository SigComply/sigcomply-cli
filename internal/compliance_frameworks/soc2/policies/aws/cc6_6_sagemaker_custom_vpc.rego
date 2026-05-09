# METADATA
# title: CC6.6 - SageMaker Custom VPC
# description: SageMaker notebook instances must be deployed in a custom VPC
# scope: package
package sigcomply.soc2.cc6_6_sagemaker_vpc

metadata := {
	"id": "soc2-cc6.6-sagemaker-custom-vpc",
	"name": "SageMaker Custom VPC",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sagemaker:notebook"],
	"remediation": "Deploy SageMaker notebook instances in a custom VPC by specifying a subnet ID.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:sagemaker:notebook"
	input.data.subnet_id == ""
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SageMaker notebook '%s' is not deployed in a custom VPC", [input.data.name]),
		"details": {
			"notebook_name": input.data.name,
		},
	}
}
