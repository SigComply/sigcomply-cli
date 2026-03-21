# METADATA
# title: A1.2 - DocumentDB Backup Retention
# description: DocumentDB clusters must have a backup retention period of at least 7 days
# scope: package
package sigcomply.soc2.a1_2_documentdb_backup_retention

metadata := {
	"id": "soc2-a1.2-documentdb-backup-retention",
	"name": "DocumentDB Backup Retention",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:documentdb:cluster"],
	"remediation": "Set the backup retention period to at least 7 days on the DocumentDB cluster to ensure sufficient recovery window.",
}

violations contains violation if {
	input.resource_type == "aws:documentdb:cluster"
	input.data.backup_retention_period < 7
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DocumentDB cluster '%s' has a backup retention period of %d days (minimum 7 required)", [input.data.cluster_id, input.data.backup_retention_period]),
		"details": {
			"cluster_id": input.data.cluster_id,
			"backup_retention_period": input.data.backup_retention_period,
		},
	}
}
