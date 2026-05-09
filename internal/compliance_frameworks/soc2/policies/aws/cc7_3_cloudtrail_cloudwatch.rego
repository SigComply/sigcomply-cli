# METADATA
# title: CC7.3 - CloudTrail CloudWatch Integration for Event Evaluation
# description: CloudTrail should integrate with CloudWatch for real-time security event evaluation
# scope: package
package sigcomply.soc2.cc7_3_cloudtrail_cloudwatch

metadata := {
	"id": "soc2-cc7.3-cloudtrail-cloudwatch",
	"name": "CloudTrail CloudWatch Integration for Event Evaluation",
	"framework": "soc2",
	"control": "CC7.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Configure CloudWatch Logs integration for real-time security event analysis.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.cloudwatch_logs_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' does not have CloudWatch integration for security event evaluation", [input.data.name]),
		"details": {"trail_name": input.data.name},
	}
}
