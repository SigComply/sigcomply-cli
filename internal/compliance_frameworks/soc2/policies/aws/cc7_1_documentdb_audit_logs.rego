# METADATA
# title: CC7.1 - DocumentDB Audit Logs
# description: DocumentDB clusters must have audit logging enabled via CloudWatch Logs
# scope: package
package sigcomply.soc2.cc7_1_documentdb_audit_logs

metadata := {
	"id": "soc2-cc7.1-documentdb-audit-logs",
	"name": "DocumentDB Audit Logs Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:documentdb:cluster"],
	"remediation": "Enable audit log exports to CloudWatch Logs on the DocumentDB cluster by adding 'audit' to the EnableCloudwatchLogsExports parameter.",
}

violations contains violation if {
	input.resource_type == "aws:documentdb:cluster"
	input.data.audit_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DocumentDB cluster '%s' does not have audit logging enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
