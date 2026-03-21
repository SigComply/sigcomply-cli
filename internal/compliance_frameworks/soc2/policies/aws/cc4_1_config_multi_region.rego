# METADATA
# title: CC4.1 - AWS Config Multi-Region Recording
# description: AWS Config must be recording across all collected regions
# scope: package
package sigcomply.soc2.cc4_1_config_multi_region

metadata := {
	"id": "soc2-cc4.1-config-multi-region",
	"name": "AWS Config Multi-Region Recording",
	"framework": "soc2",
	"control": "CC4.1",
	"severity": "high",
	"evaluation_mode": "batched",
	"resource_types": ["aws:config:recorder"],
	"remediation": "Enable AWS Config in all regions: aws configservice start-configuration-recorder --region <region>",
}

# Find regions where Config is not recording
non_recording_regions contains region if {
	some i
	input.resources[i].data.enabled == false
	region := input.resources[i].data.region
}

# Violation: some regions not recording
violations contains violation if {
	count(non_recording_regions) > 0
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": sprintf("AWS Config is not recording in %d region(s): %s", [count(non_recording_regions), concat(", ", non_recording_regions)]),
		"details": {
			"non_recording_regions": non_recording_regions,
			"total_regions": count(input.resources),
		},
	}
}

# Violation: no Config recorders exist
violations contains violation if {
	count(input.resources) == 0
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No AWS Config recorders found. Enable AWS Config in at least one region.",
		"details": {},
	}
}
