# METADATA
# title: PI1.3 - CloudTrail Multi-Region
# description: CloudTrail trails should be multi-region to ensure comprehensive processing integrity monitoring
# scope: package
package sigcomply.soc2.pi1_3_cloudtrail_multiregion

metadata := {
	"id": "soc2-pi1.3-cloudtrail-multiregion",
	"name": "CloudTrail Multi-Region Trail",
	"framework": "soc2",
	"control": "PI1.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable multi-region on CloudTrail trail: aws cloudtrail update-trail --name <trail> --is-multi-region-trail",
}

violations contains violation if {
	input.resource_type == "aws:cloudtrail:trail"
	input.data.is_multi_region == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudTrail trail '%s' is not configured as multi-region", [input.data.name]),
		"details": {"trail_name": input.data.name},
	}
}
