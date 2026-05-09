# METADATA
# title: CC6.1 - Neptune IAM Authentication
# description: Neptune clusters should have IAM database authentication enabled
# scope: package
package sigcomply.soc2.cc6_1_neptune_iam_auth

metadata := {
	"id": "soc2-cc6.1-neptune-iam-auth",
	"name": "Neptune IAM Authentication",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:neptune:cluster"],
	"remediation": "Enable IAM authentication: aws neptune modify-db-cluster --db-cluster-identifier <id> --enable-iam-database-authentication",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:neptune:cluster"
	input.data.iam_auth_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Neptune cluster '%s' does not have IAM authentication enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
