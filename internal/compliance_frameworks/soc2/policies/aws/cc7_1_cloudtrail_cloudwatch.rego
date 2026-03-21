# METADATA
# title: CC7.1 - CloudTrail CloudWatch Integration
# description: CloudTrail trails should be integrated with CloudWatch Logs for real-time monitoring
# scope: package
package sigcomply.soc2.cc7_1_cloudtrail_cloudwatch

metadata := {
	"id": "soc2-cc7.1-cloudtrail-cloudwatch",
	"name": "CloudTrail CloudWatch Integration",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Configure CloudWatch Logs delivery for the CloudTrail trail to enable real-time monitoring and alerting.",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.cloudwatch_logs_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' is not integrated with CloudWatch Logs", [input.data.name]),
		"details": {
			"trail_name": input.data.name,
		},
	}
}
