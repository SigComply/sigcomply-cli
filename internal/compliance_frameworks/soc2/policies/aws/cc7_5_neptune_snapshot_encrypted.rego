# METADATA
# title: CC7.5 - Neptune Cluster Encryption
# description: Neptune clusters should have storage encryption for secure recovery
# scope: package
package sigcomply.soc2.cc7_5_neptune_snapshot_encrypted

metadata := {
	"id": "soc2-cc7.5-neptune-snapshot-encrypted",
	"name": "Neptune Cluster Encryption",
	"framework": "soc2",
	"control": "CC7.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:neptune:cluster"],
	"remediation": "Enable storage encryption on Neptune cluster (requires recreation).",
}

violations contains violation if {
	input.resource_type == "aws:neptune:cluster"
	input.data.storage_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Neptune cluster '%s' does not have storage encryption enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
