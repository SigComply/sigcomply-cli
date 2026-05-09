# METADATA
# title: CC7.5 - Neptune Copy Tags to Snapshots
# description: Neptune clusters should copy tags to snapshots for tracking during recovery
# scope: package
package sigcomply.soc2.cc7_5_neptune_copy_tags

metadata := {
	"id": "soc2-cc7.5-neptune-copy-tags",
	"name": "Neptune Copy Tags to Snapshots",
	"framework": "soc2",
	"control": "CC7.5",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:neptune:cluster"],
	"remediation": "Enable copy tags to snapshots on the Neptune cluster.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:neptune:cluster"
	input.data.copy_tags_to_snapshot == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Neptune cluster '%s' does not copy tags to snapshots", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
