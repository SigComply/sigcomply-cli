# METADATA
# title: CC6.6 - EC2 AMI Not Publicly Shared
# description: EC2 AMIs should not be publicly shared
# scope: package
package sigcomply.soc2.cc6_6_ec2_ami_public

metadata := {
	"id": "soc2-cc6.6-ec2-ami-public",
	"name": "EC2 AMI Not Publicly Shared",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:ami"],
	"remediation": "Modify AMI permissions to remove public access.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:ami"
	input.data.public == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EC2 AMI '%s' is publicly shared", [input.data.image_id]),
		"details": {"image_id": input.data.image_id},
	}
}
