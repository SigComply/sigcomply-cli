# METADATA
# title: CC7.1 - RDS Log Publishing to CloudWatch
# description: RDS instances should publish database logs to CloudWatch Logs
# scope: package
package sigcomply.soc2.cc7_1_rds_log_publishing

metadata := {
	"id": "soc2-cc7.1-rds-log-publishing",
	"name": "RDS Log Publishing to CloudWatch",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:rds:instance"],
	"remediation": "Enable CloudWatch Logs publishing for your RDS instance: aws rds modify-db-instance --db-instance-identifier <id> --cloudwatch-logs-export-configuration EnableLogTypes=[audit,error,general,slowquery]",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:rds:instance"
	input.data.enabled_cloudwatch_logs == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("RDS instance '%s' does not publish logs to CloudWatch", [input.data.db_instance_id]),
		"details": {
			"db_instance_id": input.data.db_instance_id,
			"engine": input.data.engine,
		},
	}
}
