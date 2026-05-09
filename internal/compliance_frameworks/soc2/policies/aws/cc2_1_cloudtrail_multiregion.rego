# METADATA
# title: CC2.1 - CloudTrail Multi-Region
# description: CloudTrail should be multi-region for comprehensive information capture
# scope: package
package sigcomply.soc2.cc2_1_cloudtrail_multiregion

metadata := {
	"id": "soc2-cc2.1-cloudtrail-multiregion",
	"name": "CloudTrail Multi-Region for Information Capture",
	"framework": "soc2",
	"control": "CC2.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable multi-region on CloudTrail trail for comprehensive event logging.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.is_multi_region == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' is not multi-region for comprehensive information capture", [input.data.name]),
		"details": {"trail_name": input.data.name},
	}
}
