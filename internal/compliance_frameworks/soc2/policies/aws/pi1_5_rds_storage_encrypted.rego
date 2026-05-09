# METADATA
# title: PI1.5 - RDS Storage Encryption
# description: RDS instances should have storage encryption enabled
# scope: package
package sigcomply.soc2.pi1_5_rds_storage_encrypted

metadata := {
	"id": "soc2-pi1.5-rds-storage-encrypted",
	"name": "RDS Storage Encryption",
	"framework": "soc2",
	"control": "PI1.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable storage encryption on the RDS instance (requires recreation for existing instances).",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.storage_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have storage encryption enabled", [input.data.db_instance_id]),
		"details": {"db_instance_id": input.data.db_instance_id},
	}
}
