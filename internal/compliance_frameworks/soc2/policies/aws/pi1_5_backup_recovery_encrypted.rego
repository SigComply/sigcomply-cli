# METADATA
# title: PI1.5 - Backup Recovery Point Encryption
# description: Backup recovery points should be encrypted for data integrity
# scope: package
package sigcomply.soc2.pi1_5_backup_recovery_encrypted

metadata := {
	"id": "soc2-pi1.5-backup-recovery-encrypted",
	"name": "Backup Recovery Point Encryption",
	"framework": "soc2",
	"control": "PI1.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:backup:recovery-point"],
	"remediation": "Ensure backup recovery points are encrypted with KMS.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:backup:recovery-point"
	input.data.encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Backup recovery point is not encrypted",
		"details": {},
	}
}
