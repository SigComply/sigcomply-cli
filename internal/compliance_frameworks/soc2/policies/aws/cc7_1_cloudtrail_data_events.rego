# METADATA
# title: CC7.1 - CloudTrail Data Events
# description: At least one CloudTrail trail should have S3 data events enabled
# scope: package
package sigcomply.soc2.cc7_1_cloudtrail_data_events

metadata := {
	"id": "soc2-cc7.1-cloudtrail-data-events",
	"name": "CloudTrail Data Events Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "batched",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable S3 data events on a trail: aws cloudtrail put-event-selectors --trail-name <trail> --event-selectors '[{\"DataResources\":[{\"Type\":\"AWS::S3::Object\",\"Values\":[\"arn:aws:s3\"]}]}]'",
	"evidence_type": "automated",
}

default any_s3_data_events := false

any_s3_data_events if {
	some i
	input.resources[i].data.has_s3_data_events == true
}

# Violation: no trail has S3 data events
violations contains violation if {
	count(input.resources) > 0
	not any_s3_data_events
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail has S3 data events enabled. Enable data events for object-level logging.",
		"details": {
			"total_trails": count(input.resources),
		},
	}
}

# Violation: no trails exist
violations contains violation if {
	count(input.resources) == 0
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trails configured. Create a trail with data events enabled.",
		"details": {},
	}
}
