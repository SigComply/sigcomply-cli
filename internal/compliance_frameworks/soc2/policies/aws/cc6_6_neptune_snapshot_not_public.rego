# METADATA
# title: CC6.6 - Neptune Snapshot Not Public
# description: Neptune cluster snapshots should not be publicly accessible
# scope: package
package sigcomply.soc2.cc6_6_neptune_snapshot_not_public

metadata := {
	"id": "soc2-cc6.6-neptune-snapshot-not-public",
	"name": "Neptune Snapshot Not Public",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:neptune:snapshot"],
	"remediation": "Modify the Neptune snapshot to remove public access: aws neptune modify-db-cluster-snapshot-attribute --db-cluster-snapshot-identifier <id> --attribute-name restore --values-to-remove all",
}

violations contains violation if {
	input.resource_type == "aws:neptune:snapshot"
	input.data.is_public == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Neptune snapshot '%s' is publicly accessible", [input.data.snapshot_id]),
		"details": {"snapshot_id": input.data.snapshot_id},
	}
}
