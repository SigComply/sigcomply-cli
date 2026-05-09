# METADATA
# title: CC6.6 - Redshift Public Access
# description: Redshift clusters should not be publicly accessible
# scope: package
package sigcomply.soc2.cc6_6_redshift_public

metadata := {
	"id": "soc2-cc6.6-redshift-public",
	"name": "Redshift Public Access",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift:cluster"],
	"remediation": "Modify the Redshift cluster to disable public accessibility. Use VPC endpoints or private subnets for access.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:redshift:cluster"
	input.data.publicly_accessible == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift cluster '%s' is publicly accessible", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
