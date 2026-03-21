# METADATA
# title: CC7.5 - Redshift Automated Snapshots for Recovery
# description: Redshift clusters should have automated snapshots for incident recovery
# scope: package
package sigcomply.soc2.cc7_5_redshift_snapshot

metadata := {
	"id": "soc2-cc7.5-redshift-snapshot",
	"name": "Redshift Automated Snapshots for Recovery",
	"framework": "soc2",
	"control": "CC7.5",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift:cluster"],
	"remediation": "Enable automated snapshots with appropriate retention period.",
}

violations contains violation if {
	input.resource_type == "aws:redshift:cluster"
	input.data.automated_snapshot_retention == 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift cluster '%s' does not have automated snapshots for incident recovery", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
