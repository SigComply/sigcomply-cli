# METADATA
# title: CC7.1 - Step Functions Logging
# description: Step Functions state machines must have CloudWatch logging enabled
# scope: package
package sigcomply.soc2.cc7_1_stepfunctions_logging

metadata := {
	"id": "soc2-cc7.1-stepfunctions-logging",
	"name": "Step Functions Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:stepfunctions:state-machine"],
	"remediation": "Enable CloudWatch logging for Step Functions state machines: aws stepfunctions update-state-machine --state-machine-arn <arn> --logging-configuration level=ALL,includeExecutionData=true,destinations=[{cloudWatchLogsLogGroup:{logGroupArn=<log-group-arn>}}]",
}

violations contains violation if {
	input.resource_type == "aws:stepfunctions:state-machine"
	input.data.logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Step Functions state machine '%s' does not have CloudWatch logging enabled", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
