# METADATA
# title: CC6.6 - DocumentDB Snapshot Not Public
# description: DocumentDB cluster snapshots must not be publicly accessible
# scope: package
package sigcomply.soc2.cc6_6_documentdb_snapshot_not_public

metadata := {
	"id": "soc2-cc6.6-documentdb-snapshot-not-public",
	"name": "DocumentDB Snapshot Not Public",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:documentdb:snapshot"],
	"remediation": "Remove public access from DocumentDB snapshots. Use aws rds modify-db-cluster-snapshot-attribute to revoke public access.",
}

violations contains violation if {
	input.resource_type == "aws:documentdb:snapshot"
	input.data.is_public == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DocumentDB snapshot '%s' is publicly accessible", [input.data.snapshot_id]),
		"details": {"snapshot_id": input.data.snapshot_id},
	}
}
