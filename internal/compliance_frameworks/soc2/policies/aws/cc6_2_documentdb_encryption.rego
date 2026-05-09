# METADATA
# title: CC6.2 - DocumentDB Encryption at Rest
# description: All DocumentDB clusters must have encryption at rest enabled
# scope: package
package sigcomply.soc2.cc6_2_documentdb_encryption

metadata := {
	"id": "soc2-cc6.2-documentdb-encryption",
	"name": "DocumentDB Encryption at Rest",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:documentdb:cluster"],
	"remediation": "Enable encryption at rest when creating DocumentDB clusters. Existing unencrypted clusters must be migrated by creating an encrypted snapshot and restoring from it.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:documentdb:cluster"
	input.data.storage_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DocumentDB cluster '%s' does not have encryption at rest enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
