# METADATA
# title: CC7.5 - RDS Aurora Cluster Encryption
# description: Aurora clusters should have storage encryption enabled for recovery
# scope: package
package sigcomply.soc2.cc7_5_rds_cluster_encrypted

metadata := {
	"id": "soc2-cc7.5-rds-cluster-encrypted",
	"name": "Aurora Cluster Encryption",
	"framework": "soc2",
	"control": "CC7.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:cluster"],
	"remediation": "Enable storage encryption on the Aurora cluster (requires recreation).",
}

violations contains violation if {
	input.resource_type == "aws:rds:cluster"
	input.data.storage_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Aurora cluster '%s' does not have storage encryption enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
