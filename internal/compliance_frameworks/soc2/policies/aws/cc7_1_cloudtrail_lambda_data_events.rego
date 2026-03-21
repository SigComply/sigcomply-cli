# METADATA
# title: CC7.1 - CloudTrail Lambda Data Events
# description: At least one CloudTrail trail should have Lambda data events enabled
# scope: package
package sigcomply.soc2.cc7_1_cloudtrail_lambda_data_events

metadata := {
	"id": "soc2-cc7.1-cloudtrail-lambda-data-events",
	"name": "CloudTrail Lambda Data Events Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "batched",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable Lambda data events on a trail: aws cloudtrail put-event-selectors --trail-name <trail> --event-selectors '[{\"DataResources\":[{\"Type\":\"AWS::Lambda::Function\",\"Values\":[\"arn:aws:lambda\"]}]}]'",
}

default any_lambda_data_events := false

any_lambda_data_events if {
	some i
	input.resources[i].data.has_lambda_data_events == true
}

# Violation: no trail has Lambda data events
violations contains violation if {
	count(input.resources) > 0
	not any_lambda_data_events
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail has Lambda data events enabled. Enable data events for function-level logging.",
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
		"reason": "No CloudTrail trails configured. Create a trail with Lambda data events enabled.",
		"details": {},
	}
}
