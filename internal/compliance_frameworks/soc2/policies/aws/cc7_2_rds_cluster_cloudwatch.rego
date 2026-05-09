# METADATA
# title: CC7.2 - Aurora Cluster CloudWatch Logs
# description: Aurora clusters should publish logs to CloudWatch for monitoring
# scope: package
package sigcomply.soc2.cc7_2_rds_cluster_cloudwatch

metadata := {
	"id": "soc2-cc7.2-rds-cluster-cloudwatch",
	"name": "Aurora Cluster CloudWatch Logs",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:cluster"],
	"remediation": "Enable CloudWatch log publishing for the Aurora cluster.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:cluster"
	input.data.enabled_cloudwatch_logs == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Aurora cluster '%s' does not publish logs to CloudWatch", [input.data.cluster_id]),
		"details": {"cluster_id": input.data.cluster_id},
	}
}
