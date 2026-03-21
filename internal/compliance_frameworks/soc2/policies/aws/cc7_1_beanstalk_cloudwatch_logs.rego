# METADATA
# title: CC7.1 - Elastic Beanstalk CloudWatch Logs Streaming
# description: Elastic Beanstalk environments must have CloudWatch log streaming enabled
# scope: package
package sigcomply.soc2.cc7_1_beanstalk_cloudwatch_logs

metadata := {
	"id": "soc2-cc7.1-beanstalk-cloudwatch-logs",
	"name": "Elastic Beanstalk CloudWatch Logs Streaming",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:elasticbeanstalk:environment"],
	"remediation": "Enable CloudWatch log streaming on the Elastic Beanstalk environment by setting StreamLogs to true in the aws:elasticbeanstalk:cloudwatch:logs namespace.",
}

violations contains violation if {
	input.resource_type == "aws:elasticbeanstalk:environment"
	input.data.cloudwatch_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Elastic Beanstalk environment '%s' does not have CloudWatch log streaming enabled", [input.data.environment_name]),
		"details": {"environment_name": input.data.environment_name},
	}
}
