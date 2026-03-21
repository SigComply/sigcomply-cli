# METADATA
# title: CC7.2 - CIS Metric Filter for AWS Config Changes
# description: A metric filter and alarm should exist for AWS Config configuration changes
# scope: package
package sigcomply.soc2.cc7_2_cis_config_changes

metadata := {
	"id": "soc2-cc7.2-cis-config-changes",
	"name": "CIS Alarm - AWS Config Changes",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for AWS Config changes (StopConfigurationRecorder, DeleteDeliveryChannel, PutConfigurationRecorder, PutDeliveryChannel) and associate an SNS alarm.",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "config_changes"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for AWS Config changes (CIS 4.9)",
		"details": {
			"cis_control": "4.9",
			"filter_name": "config_changes",
		},
	}
}
