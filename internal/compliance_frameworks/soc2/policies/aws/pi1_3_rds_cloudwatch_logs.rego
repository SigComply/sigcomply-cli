# METADATA
# title: PI1.3 - RDS CloudWatch Log Integration
# description: RDS instances should publish logs to CloudWatch for processing integrity monitoring
# scope: package
package sigcomply.soc2.pi1_3_rds_cloudwatch_logs

metadata := {
	"id": "soc2-pi1.3-rds-cloudwatch-logs",
	"name": "RDS CloudWatch Log Integration",
	"framework": "soc2",
	"control": "PI1.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable CloudWatch log publishing for the RDS instance.",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.enabled_cloudwatch_logs == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not publish logs to CloudWatch", [input.data.db_instance_id]),
		"details": {"db_instance_id": input.data.db_instance_id},
	}
}
