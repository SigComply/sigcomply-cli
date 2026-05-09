# METADATA
# title: CC7.4 - EFS Backup Enabled
# description: EFS file systems should have automatic backup enabled for incident response
# scope: package
package sigcomply.soc2.cc7_4_efs_backup

metadata := {
	"id": "soc2-cc7.4-efs-backup",
	"name": "EFS Backup Enabled",
	"framework": "soc2",
	"control": "CC7.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:efs:file_system"],
	"remediation": "Enable automatic backup for the EFS file system.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:efs:file_system"
	input.data.backup_policy_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EFS file system '%s' does not have backup enabled", [input.data.file_system_id]),
		"details": {"file_system_id": input.data.file_system_id},
	}
}
