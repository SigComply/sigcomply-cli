# METADATA
# title: CC6.1 - Redshift Default Admin Username
# description: Redshift clusters must not use default or common admin usernames
# scope: package
package sigcomply.soc2.cc6_1_redshift_no_default_admin

metadata := {
	"id": "soc2-cc6.1-redshift-no-default-admin",
	"name": "Redshift Default Admin Username",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift:cluster"],
	"remediation": "Create a new Redshift cluster with a custom master username. Default usernames like 'admin', 'awsuser', 'master', or 'root' are easily guessable.",
	"evidence_type": "automated",
}

default_usernames := {"admin", "awsuser", "master", "root"}

violations contains violation if {
	input.resource_type == "aws:redshift:cluster"
	lower(input.data.master_username) == default_usernames[_]
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift cluster '%s' uses a default admin username '%s'", [input.data.cluster_id, input.data.master_username]),
		"details": {
			"cluster_id": input.data.cluster_id,
		},
	}
}
