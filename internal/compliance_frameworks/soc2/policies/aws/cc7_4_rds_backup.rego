# METADATA
# title: CC7.4 - RDS Backup Retention
# description: RDS instances should have backup retention period greater than zero
# scope: package
package sigcomply.soc2.cc7_4_rds_backup

metadata := {
	"id": "soc2-cc7.4-rds-backup",
	"name": "RDS Backup Retention",
	"framework": "soc2",
	"control": "CC7.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Set backup retention period to at least 7 days for the RDS instance.",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.backup_retention_period == 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' has backup retention period of 0 days", [input.data.db_instance_id]),
		"details": {"db_instance_id": input.data.db_instance_id},
	}
}
