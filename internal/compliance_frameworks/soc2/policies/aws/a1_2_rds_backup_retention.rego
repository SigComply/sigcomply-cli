# METADATA
# title: A1.2 - RDS Backup Retention Period
# description: RDS instances with backups enabled must have a retention period of at least 7 days
# scope: package
package sigcomply.soc2.a1_2_backup_retention

metadata := {
	"id": "soc2-a1.2-rds-backup-retention",
	"name": "RDS Backup Retention Period",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Increase the backup retention period to at least 7 days for all RDS instances with automated backups enabled.",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.backup_enabled == true
	input.data.backup_retention_period < 7
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' has backup retention of %d days (minimum 7 required)", [input.data.db_instance_id, input.data.backup_retention_period]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"backup_retention_period": input.data.backup_retention_period,
		},
	}
}
