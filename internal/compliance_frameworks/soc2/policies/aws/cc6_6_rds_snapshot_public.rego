# METADATA
# title: CC6.6 - RDS Snapshot Public Sharing
# description: RDS snapshots should not be publicly shared
# scope: package
package sigcomply.soc2.cc6_6_rds_snapshot_public

metadata := {
	"id": "soc2-cc6.6-rds-snapshot-public",
	"name": "RDS Snapshot Public Sharing",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:snapshot"],
	"remediation": "Modify the RDS snapshot to remove public access. Share snapshots only with specific AWS accounts.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:snapshot"
	input.data.public == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS snapshot '%s' is publicly shared", [input.data.snapshot_id]),
		"details": {
			"snapshot_id": input.data.snapshot_id,
			"db_instance_id": input.data.db_instance_id,
		},
	}
}
