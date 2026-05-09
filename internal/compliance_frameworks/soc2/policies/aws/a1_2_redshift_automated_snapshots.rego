# METADATA
# title: A1.2 - Redshift Automated Snapshots
# description: Redshift clusters should have automated snapshots enabled with adequate retention
# scope: package
package sigcomply.soc2.a1_2_redshift_automated_snapshots

metadata := {
	"id": "soc2-a1.2-redshift-automated-snapshots",
	"name": "Redshift Automated Snapshots",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift:cluster"],
	"remediation": "Enable automated snapshots: aws redshift modify-cluster --cluster-identifier <id> --automated-snapshot-retention-period 7",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:redshift:cluster"
	input.data.automated_snapshot_retention < 1
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift cluster '%s' has automated snapshots disabled (retention: %d days)", [input.data.cluster_id, input.data.automated_snapshot_retention]),
		"details": {
			"cluster_id": input.data.cluster_id,
			"retention_days": input.data.automated_snapshot_retention,
		},
	}
}
