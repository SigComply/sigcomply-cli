# METADATA
# title: CC6.6 - Account-Level Block Public Access for EBS
# description: Account-level block public access should be enabled for EBS snapshots
# scope: package
package sigcomply.soc2.cc6_6_ec2_ebs_snapshot_block_public

metadata := {
	"id": "soc2-cc6.6-ec2-ebs-snapshot-block-public",
	"name": "Account-Level Block Public Access for EBS",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:account-setting"],
	"remediation": "Enable account-level block public access for EBS snapshots.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:account-setting"
	input.data.ebs_block_public_access == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Account-level block public access for EBS snapshots is not enabled",
		"details": {},
	}
}
