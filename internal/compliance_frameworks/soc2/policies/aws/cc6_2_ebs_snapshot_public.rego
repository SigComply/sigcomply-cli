# METADATA
# title: CC6.2 - EBS Snapshot Public Sharing
# description: EBS snapshots should not be publicly shared
# scope: package
package sigcomply.soc2.cc6_2_ebs_snapshot_public

metadata := {
	"id": "soc2-cc6.2-ebs-snapshot-public",
	"name": "EBS Snapshot Public Sharing",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:ebs_snapshot"],
	"remediation": "Modify the EBS snapshot permissions to remove public access. Share snapshots only with specific AWS accounts that require access.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:ec2:ebs_snapshot"
	input.data.public == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EBS snapshot '%s' is publicly shared", [input.data.snapshot_id]),
		"details": {
			"snapshot_id": input.data.snapshot_id,
			"volume_id": input.data.volume_id,
		},
	}
}
