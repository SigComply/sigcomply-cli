# METADATA
# title: A1.2 - EFS Backup Policy
# description: EFS file systems must have backup policy enabled
# scope: package
package sigcomply.soc2.a1_2_efs_backup

metadata := {
	"id": "soc2-a1.2-efs-backup",
	"name": "EFS Backup Policy Enabled",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:efs:file_system"],
	"remediation": "Enable backup policy: aws efs put-backup-policy --file-system-id FS_ID --backup-policy Status=ENABLED",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:efs:file_system"
	input.data.backup_policy_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("EFS file system '%s' does not have backup policy enabled", [input.data.file_system_id]),
		"details": {"file_system_id": input.data.file_system_id},
	}
}
