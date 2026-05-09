# METADATA
# title: A1.2 - DocumentDB Deletion Protection
# description: DocumentDB clusters must have deletion protection enabled to prevent accidental data loss
# scope: package
package sigcomply.soc2.a1_2_documentdb_deletion_protection

metadata := {
	"id": "soc2-a1.2-documentdb-deletion-protection",
	"name": "DocumentDB Deletion Protection Enabled",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:documentdb:cluster"],
	"remediation": "Enable deletion protection on the DocumentDB cluster to prevent accidental deletion. Use the AWS console or CLI: aws docdb modify-db-cluster --db-cluster-identifier CLUSTER_ID --deletion-protection.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:documentdb:cluster"
	input.data.deletion_protection == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DocumentDB cluster '%s' does not have deletion protection enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
