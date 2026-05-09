# METADATA
# title: CC7.2 - CloudTrail SNS Notifications
# description: CloudTrail trails should have SNS topic configured for event notifications
# scope: package
package sigcomply.soc2.cc7_2_cloudtrail_sns

metadata := {
	"id": "soc2-cc7.2-cloudtrail-sns",
	"name": "CloudTrail SNS Notifications",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Configure an SNS topic for the CloudTrail trail to receive notifications for API activity.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.sns_topic_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' does not have SNS notifications configured", [input.data.name]),
		"details": {
			"trail_name": input.data.name,
		},
	}
}
