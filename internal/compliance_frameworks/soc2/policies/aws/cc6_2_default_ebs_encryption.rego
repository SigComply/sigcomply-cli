# METADATA
# title: CC6.2 - Default EBS Encryption
# description: EBS encryption by default should be enabled at the account level
# scope: package
package sigcomply.soc2.cc6_2_default_ebs_encryption

metadata := {
	"id": "soc2-cc6.2-default-ebs-encryption",
	"name": "Default EBS Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:ebs-encryption"],
	"remediation": "Enable EBS encryption by default in the EC2 console or via the AWS CLI to ensure all new EBS volumes are automatically encrypted.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:ebs-encryption"
	input.data.encryption_by_default == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "EBS encryption by default is not enabled for this region",
		"details": {"region": input.data.region},
	}
}
