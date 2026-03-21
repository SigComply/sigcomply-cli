# METADATA
# title: CC7.2 - CIS Metric Filter for CMK Disabling or Deletion
# description: A metric filter and alarm should exist for disabling or scheduled deletion of CMKs
# scope: package
package sigcomply.soc2.cc7_2_cis_cmk_disable_deletion

metadata := {
	"id": "soc2-cc7.2-cis-cmk-disable-deletion",
	"name": "CIS Alarm - CMK Disabling/Deletion",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for KMS DisableKey and ScheduleKeyDeletion events and associate an SNS alarm.",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "cmk_disable_deletion"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for CMK disabling or scheduled deletion (CIS 4.7)",
		"details": {
			"cis_control": "4.7",
			"filter_name": "cmk_disable_deletion",
		},
	}
}
