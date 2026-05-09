# METADATA
# title: A1.2 - Database Backup and PITR
# description: Database instances must have automated backups and point-in-time recovery enabled
# scope: package
package sigcomply.soc2.a1_2_backup

metadata := {
	"id": "soc2-a1.2-db-backup",
	"name": "Database Backup and PITR",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance", "gcp:sql:instance"],
	"remediation": "Enable automated backups with point-in-time recovery for all database instances.",
	"evidence_type": "automated",
}

# AWS RDS
violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.backup_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have automated backups enabled", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"backup_retention_period": input.data.backup_retention_period,
		},
	}
}

# GCP Cloud SQL
violations contains violation if {
	input.resource_type == "gcp:sql:instance"
	input.data.backup_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud SQL instance '%s' does not have automated backups enabled", [input.data.name]),
		"details": {
			"instance_name": input.data.name,
		},
	}
}

violations contains violation if {
	input.resource_type == "gcp:sql:instance"
	input.data.backup_enabled == true
	input.data.pitr_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cloud SQL instance '%s' does not have point-in-time recovery enabled", [input.data.name]),
		"details": {
			"instance_name": input.data.name,
			"severity_override": "medium",
		},
	}
}
