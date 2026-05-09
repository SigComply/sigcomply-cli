# METADATA
# title: A1.2 - Neptune Backup Retention
# description: Neptune clusters should have adequate backup retention (at least 7 days)
# scope: package
package sigcomply.soc2.a1_2_neptune_backup_retention

metadata := {
	"id": "soc2-a1.2-neptune-backup-retention",
	"name": "Neptune Backup Retention",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:neptune:cluster"],
	"remediation": "Increase backup retention period: aws neptune modify-db-cluster --db-cluster-identifier <id> --backup-retention-period 7",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:neptune:cluster"
	input.data.backup_retention_period < 7
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Neptune cluster '%s' has insufficient backup retention (%d days, minimum 7 required)", [input.data.cluster_id, input.data.backup_retention_period]),
		"details": {
			"cluster_id": input.data.cluster_id,
			"backup_retention_period": input.data.backup_retention_period,
		},
	}
}
