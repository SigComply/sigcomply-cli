# METADATA
# title: CC6.2 - EBS Default Encryption
# description: EBS default encryption must be enabled per region
# scope: package
package sigcomply.soc2.cc6_2_ebs

metadata := {
	"id": "soc2-cc6.2-ebs-encryption",
	"name": "EBS Default Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:ebs-encryption"],
	"remediation": "Enable EBS default encryption: aws ec2 enable-ebs-encryption-by-default --region <region>",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:ebs-encryption"
	input.data.encryption_by_default == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EBS default encryption is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
		},
	}
}
