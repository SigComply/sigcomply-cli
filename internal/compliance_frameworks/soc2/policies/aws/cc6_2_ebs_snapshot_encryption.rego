# METADATA
# title: CC6.2 - EBS Snapshot Encryption
# description: EBS snapshots should be encrypted at rest
# scope: package
package sigcomply.soc2.cc6_2_ebs_snapshot_encryption

metadata := {
	"id": "soc2-cc6.2-ebs-snapshot-encryption",
	"name": "EBS Snapshot Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:ebs_snapshot"],
	"remediation": "Create encrypted copies of unencrypted snapshots: aws ec2 copy-snapshot --source-snapshot-id <id> --encrypted. Delete the unencrypted originals after verification.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:ebs_snapshot"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EBS snapshot '%s' is not encrypted", [input.data.snapshot_id]),
		"details": {
			"snapshot_id": input.data.snapshot_id,
			"volume_id": input.data.volume_id,
		},
	}
}
