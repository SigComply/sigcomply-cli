# METADATA
# title: CC7.5 - EBS Snapshot Encryption
# description: EBS snapshots should be encrypted for secure incident recovery
# scope: package
package sigcomply.soc2.cc7_5_ebs_snapshots_encrypted

metadata := {
	"id": "soc2-cc7.5-ebs-snapshots-encrypted",
	"name": "EBS Snapshot Encryption",
	"framework": "soc2",
	"control": "CC7.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:ec2:ebs_snapshot"],
	"remediation": "Ensure EBS snapshots are created from encrypted volumes or copy with encryption enabled.",
}

violations contains violation if {
	input.resource_type == "aws:ec2:ebs_snapshot"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EBS snapshot '%s' is not encrypted", [input.data.snapshot_id]),
		"details": {"snapshot_id": input.data.snapshot_id},
	}
}
