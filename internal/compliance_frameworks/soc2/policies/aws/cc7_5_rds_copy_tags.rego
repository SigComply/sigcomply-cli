# METADATA
# title: CC7.5 - RDS Copy Tags to Snapshots
# description: RDS instances should copy tags to snapshots for tracking during recovery
# scope: package
package sigcomply.soc2.cc7_5_rds_copy_tags

metadata := {
	"id": "soc2-cc7.5-rds-copy-tags",
	"name": "RDS Copy Tags to Snapshots",
	"framework": "soc2",
	"control": "CC7.5",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable copy tags to snapshots on the RDS instance.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.copy_tags_to_snapshot == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not copy tags to snapshots", [input.data.db_instance_id]),
		"details": {"db_instance_id": input.data.db_instance_id},
	}
}
