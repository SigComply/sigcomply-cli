# METADATA
# title: CC7.3 - CloudWatch No Unauthorized Cross-Account Sharing
# description: CloudWatch Log Groups should not have unauthorized cross-account sharing
# scope: package
package sigcomply.soc2.cc7_3_cloudwatch_no_cross_account

metadata := {
	"id": "soc2-cc7.3-cloudwatch-no-cross-account",
	"name": "CloudWatch No Unauthorized Cross-Account Sharing",
	"framework": "soc2",
	"control": "CC7.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:logs:log-group"],
	"remediation": "Review and restrict cross-account sharing on the CloudWatch Log Group.",
}

violations contains violation if {
	input.resource_type == "aws:logs:log-group"
	input.data.has_cross_account_sharing == true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("CloudWatch Log Group '%s' has cross-account sharing enabled", [input.data.name]),
		"details": {"log_group_name": input.data.name},
	}
}
