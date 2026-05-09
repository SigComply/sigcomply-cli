# METADATA
# title: PI1.5 - EBS Volume Encryption
# description: EBS volumes should have encryption enabled
# scope: package
package sigcomply.soc2.pi1_5_ebs_encryption

metadata := {
	"id": "soc2-pi1.5-ebs-encryption",
	"name": "EBS Volume Encryption",
	"framework": "soc2",
	"control": "PI1.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:volume"],
	"remediation": "Enable encryption on EBS volumes. Use account-level default encryption for new volumes.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:volume"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EBS volume '%s' is not encrypted", [input.resource_id]),
		"details": {},
	}
}
