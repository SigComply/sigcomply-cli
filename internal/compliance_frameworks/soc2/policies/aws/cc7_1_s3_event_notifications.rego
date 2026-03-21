# METADATA
# title: CC7.1 - S3 Event Notifications
# description: S3 buckets should have event notifications configured for monitoring
# scope: package
package sigcomply.soc2.cc7_1_s3_event_notifications

metadata := {
	"id": "soc2-cc7.1-s3-event-notifications",
	"name": "S3 Event Notifications Configured",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "low",
	"evaluation_mode": "individual",
	"resource_types": ["aws:s3:bucket"],
	"remediation": "Configure event notifications: aws s3api put-bucket-notification-configuration --bucket <bucket> --notification-configuration file://notification.json",
}

violations contains violation if {
	input.resource_type == "aws:s3:bucket"
	input.data.event_notifications_configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("S3 bucket '%s' does not have event notifications configured", [input.data.name]),
		"details": {
			"bucket_name": input.data.name,
		},
	}
}
