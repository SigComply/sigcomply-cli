# METADATA
# title: PI1.5 - Backup Vault Encryption
# description: AWS Backup vaults should use encryption for stored backups
# scope: package
package sigcomply.soc2.pi1_5_backup_encrypted

metadata := {
	"id": "soc2-pi1.5-backup-encrypted",
	"name": "Backup Vault Encryption",
	"framework": "soc2",
	"control": "PI1.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:backup:vault"],
	"remediation": "Ensure the AWS Backup vault uses KMS encryption.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:backup:vault"
	input.data.encryption_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Backup vault does not have encryption enabled",
		"details": {},
	}
}
