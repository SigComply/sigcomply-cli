# METADATA
# title: CC7.1 - CloudTrail Multi-Region Enabled
# description: At least one CloudTrail trail must be configured for multi-region logging
# scope: package
package sigcomply.soc2.cc7_1_cloudtrail_multi_region

metadata := {
	"id": "soc2-cc7.1-cloudtrail-multi-region",
	"name": "CloudTrail Multi-Region Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "batched",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable multi-region on a trail: aws cloudtrail update-trail --name <trail> --is-multi-region-trail",
	"evidence_type": "automated",
}

default any_multi_region := false

any_multi_region if {
	some i
	input.resources[i].data.is_multi_region == true
}

# Violation: no trail is multi-region
violations contains violation if {
	count(input.resources) > 0
	not any_multi_region
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail is configured for multi-region logging. Enable multi-region on at least one trail for complete coverage.",
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
		"reason": "No CloudTrail trails configured. Create at least one multi-region trail.",
		"details": {},
	}
}
