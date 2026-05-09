# METADATA
# title: CC6.7 - Redshift SSL Required
# description: Redshift clusters should require SSL for connections
# scope: package
package sigcomply.soc2.cc6_7_redshift_ssl

metadata := {
	"id": "soc2-cc6.7-redshift-ssl",
	"name": "Redshift SSL Required",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift:cluster"],
	"remediation": "Enable require_ssl parameter in the Redshift parameter group: aws redshift modify-cluster-parameter-group --parameter-group-name <name> --parameters ParameterName=require_ssl,ParameterValue=true,ApplyType=static",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:redshift:cluster"
	input.data.require_ssl == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift cluster '%s' does not require SSL connections", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
