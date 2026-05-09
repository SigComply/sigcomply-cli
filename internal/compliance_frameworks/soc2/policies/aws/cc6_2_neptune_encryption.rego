# METADATA
# title: CC6.2 - Neptune Cluster Encryption at Rest
# description: Neptune clusters should have encryption at rest enabled
# scope: package
package sigcomply.soc2.cc6_2_neptune_encryption

metadata := {
	"id": "soc2-cc6.2-neptune-encryption",
	"name": "Neptune Cluster Encryption at Rest",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:neptune:cluster"],
	"remediation": "Create a new Neptune cluster with encryption enabled. Encryption cannot be enabled on existing clusters.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:neptune:cluster"
	input.data.storage_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Neptune cluster '%s' does not have encryption at rest enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
