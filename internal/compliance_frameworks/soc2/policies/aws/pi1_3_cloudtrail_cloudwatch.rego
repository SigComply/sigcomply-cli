# METADATA
# title: PI1.3 - CloudTrail CloudWatch Integration
# description: CloudTrail trails should send logs to CloudWatch for real-time processing integrity monitoring
# scope: package
package sigcomply.soc2.pi1_3_cloudtrail_cloudwatch

metadata := {
	"id": "soc2-pi1.3-cloudtrail-cloudwatch",
	"name": "CloudTrail CloudWatch Integration",
	"framework": "soc2",
	"control": "PI1.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Configure CloudWatch Logs integration for CloudTrail trail.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.cloudwatch_logs_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' does not have CloudWatch Logs integration configured", [input.data.name]),
		"details": {"trail_name": input.data.name},
	}
}
