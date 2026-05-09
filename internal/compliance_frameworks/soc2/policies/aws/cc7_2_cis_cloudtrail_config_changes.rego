# METADATA
# title: CC7.2 - CIS Metric Filter for CloudTrail Configuration Changes
# description: A metric filter and alarm should exist for CloudTrail configuration changes
# scope: package
package sigcomply.soc2.cc7_2_cis_cloudtrail_config_changes

metadata := {
	"id": "soc2-cc7.2-cis-cloudtrail-config-changes",
	"name": "CIS Alarm - CloudTrail Config Changes",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for CloudTrail configuration changes (StopLogging, DeleteTrail, UpdateTrail) and associate an SNS alarm.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "cloudtrail_config_changes"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for CloudTrail configuration changes (CIS 4.5)",
		"details": {
			"cis_control": "4.5",
			"filter_name": "cloudtrail_config_changes",
		},
	}
}
