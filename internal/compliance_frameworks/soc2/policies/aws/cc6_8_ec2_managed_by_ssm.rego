# METADATA
# title: CC6.8 - EC2 Instances Managed by SSM
# description: EC2 instances should be managed by AWS Systems Manager
# scope: package
package sigcomply.soc2.cc6_8_ec2_managed_by_ssm

metadata := {
	"id": "soc2-cc6.8-ec2-managed-by-ssm",
	"name": "EC2 Instances Managed by SSM",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:instance"],
	"remediation": "Install SSM Agent and ensure the instance has the required IAM role for SSM.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:instance"
	input.data.ssm_managed == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EC2 instance '%s' is not managed by AWS Systems Manager", [input.data.instance_id]),
		"details": {"instance_id": input.data.instance_id},
	}
}
