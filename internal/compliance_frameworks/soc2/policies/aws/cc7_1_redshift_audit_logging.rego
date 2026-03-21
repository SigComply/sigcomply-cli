# METADATA
# title: CC7.1 - Redshift Audit Logging
# description: Redshift clusters should have audit logging enabled
# scope: package
package sigcomply.soc2.cc7_1_redshift_audit_logging

metadata := {
	"id": "soc2-cc7.1-redshift-audit-logging",
	"name": "Redshift Audit Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:redshift:cluster"],
	"remediation": "Enable audit logging for the Redshift cluster to capture connection, user activity, and query logs.",
}

violations contains violation if {
	input.resource_type == "aws:redshift:cluster"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Redshift cluster '%s' does not have audit logging enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
