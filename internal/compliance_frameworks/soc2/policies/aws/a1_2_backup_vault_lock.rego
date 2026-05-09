# METADATA
# title: A1.2 - Backup Vault Lock
# description: At least one backup vault must have vault lock enabled for immutable backups
# scope: package
package sigcomply.soc2.a1_2_backup_vault_lock

metadata := {
	"id": "soc2-a1.2-backup-vault-lock",
	"name": "Backup Vault Lock",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:backup:status"],
	"remediation": "Enable vault lock on at least one AWS Backup vault to ensure backup immutability",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:backup:status"
	input.data.vault_lock_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No backup vault has vault lock enabled for immutable backups",
		"details": {
			"region": input.data.region,
		},
	}
}
