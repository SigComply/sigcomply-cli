# METADATA
# title: PI1.5 - Backup Vault Encryption Configuration
# description: Backup vaults should have vault-level encryption configured
# scope: package
package sigcomply.soc2.pi1_5_backup_vault_encrypted

metadata := {
	"id": "soc2-pi1.5-backup-vault-encrypted",
	"name": "Backup Vault Encryption Configuration",
	"framework": "soc2",
	"control": "PI1.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:backup:vault"],
	"remediation": "Configure KMS encryption on the backup vault.",
}

violations contains violation if {
	input.resource_type == "aws:backup:vault"
	input.data.kms_key_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Backup vault does not have KMS encryption configured",
		"details": {},
	}
}
