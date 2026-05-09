# METADATA
# title: CC9.3 - ElastiCache Automatic Backups Enabled
# description: ElastiCache replication groups should have automatic backups enabled
# scope: package
package sigcomply.soc2.cc9_3_elasticache_backup

metadata := {
	"id": "soc2-cc9.3-elasticache-backup",
	"name": "ElastiCache Automatic Backups Enabled",
	"framework": "soc2",
	"control": "CC9.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticache:replication_group"],
	"remediation": "Enable automatic backups for the ElastiCache replication group with an appropriate retention period.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:elasticache:replication_group"
	input.data.snapshot_retention_limit == 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("ElastiCache replication group '%s' does not have automatic backups enabled", [input.data.replication_group_id]),
		"details": {
			"replication_group_id": input.data.replication_group_id,
			"snapshot_retention_limit": input.data.snapshot_retention_limit,
		},
	}
}
