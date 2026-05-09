# METADATA
# title: CC7.1 - Neptune Audit Logs
# description: Neptune clusters should have audit logging enabled
# scope: package
package sigcomply.soc2.cc7_1_neptune_audit_logs

metadata := {
	"id": "soc2-cc7.1-neptune-audit-logs",
	"name": "Neptune Audit Logs",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:neptune:cluster"],
	"remediation": "Enable audit logging for your Neptune cluster: aws neptune modify-db-cluster --db-cluster-identifier <id> --cloudwatch-logs-export-configuration EnableLogTypes=[audit]",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:neptune:cluster"
	input.data.audit_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Neptune cluster '%s' does not have audit logging enabled", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
