# METADATA
# title: A1.2 - Neptune Deletion Protection
# description: Neptune clusters should have deletion protection enabled
# scope: package
package sigcomply.soc2.a1_2_neptune_deletion_protection

metadata := {
	"id": "soc2-a1.2-neptune-deletion-protection",
	"name": "Neptune Deletion Protection",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:neptune:cluster"],
	"remediation": "Enable deletion protection: aws neptune modify-db-cluster --db-cluster-identifier <id> --deletion-protection",
}

violations contains violation if {
	input.resource_type == "aws:neptune:cluster"
	input.data.deletion_protection == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Neptune cluster '%s' does not have deletion protection enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
