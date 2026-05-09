# METADATA
# title: CC4.2 - GuardDuty Multi-Region Enabled
# description: GuardDuty must be enabled across all collected regions
# scope: package
package sigcomply.soc2.cc4_2_guardduty_multi_region

metadata := {
	"id": "soc2-cc4.2-guardduty-multi-region",
	"name": "GuardDuty Multi-Region Coverage",
	"framework": "soc2",
	"control": "CC4.2",
	"severity": "high",
	"evaluation_mode": "batched",
	"resource_types": ["aws:guardduty:detector"],
	"remediation": "Enable GuardDuty in all regions: aws guardduty create-detector --enable --region <region>",
	"evidence_type": "automated",
}

# Find regions where GuardDuty is disabled
disabled_regions contains region if {
	some i
	input.resources[i].data.enabled == false
	region := input.resources[i].data.region
}

# Violation: some regions have GuardDuty disabled
violations contains violation if {
	count(disabled_regions) > 0
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": sprintf("GuardDuty is not enabled in %d region(s): %s", [count(disabled_regions), concat(", ", disabled_regions)]),
		"details": {
			"disabled_regions": disabled_regions,
			"total_regions": count(input.resources),
		},
	}
}
