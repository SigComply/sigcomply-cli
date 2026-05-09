# METADATA
# title: CC7.4 - Redshift Automated Snapshots
# description: Redshift clusters should have automated snapshots enabled for incident response
# scope: package
package sigcomply.soc2.cc7_4_redshift_snapshot

metadata := {
	"id": "soc2-cc7.4-redshift-snapshot",
	"name": "Redshift Automated Snapshots",
	"framework": "soc2",
	"control": "CC7.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift:cluster"],
	"remediation": "Enable automated snapshots with a retention period of at least 1 day.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:redshift:cluster"
	input.data.automated_snapshot_retention == 0
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift cluster '%s' does not have automated snapshots enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
