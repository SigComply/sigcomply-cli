# METADATA
# title: CC6.6 - Redshift Serverless Not Public
# description: Redshift Serverless workgroups should not be publicly accessible
# scope: package
package sigcomply.soc2.cc6_6_redshiftserverless_not_public

metadata := {
	"id": "soc2-cc6.6-redshiftserverless-not-public",
	"name": "Redshift Serverless Not Public",
	"framework": "soc2",
	"control": "CC6.6",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift-serverless:workgroup"],
	"remediation": "Disable public access on the Redshift Serverless workgroup.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:redshift-serverless:workgroup"
	input.data.publicly_accessible == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift Serverless workgroup '%s' is publicly accessible", [input.data.name]),
		"details": {"workgroup_name": input.data.name},
	}
}
