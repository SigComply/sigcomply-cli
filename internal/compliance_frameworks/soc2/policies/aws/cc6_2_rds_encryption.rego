# METADATA
# title: CC6.2 - RDS Encryption at Rest
# description: All RDS instances must have encryption at rest enabled
# scope: package
package sigcomply.soc2.cc6_2_rds

metadata := {
	"id": "soc2-cc6.2-rds-encryption",
	"name": "RDS Encryption at Rest",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable encryption at rest when creating RDS instances. Existing unencrypted instances must be migrated by creating an encrypted snapshot and restoring from it.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.storage_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not have encryption at rest enabled", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"engine": input.data.engine,
		},
	}
}
