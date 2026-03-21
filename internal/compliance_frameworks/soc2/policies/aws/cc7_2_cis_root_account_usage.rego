# METADATA
# title: CC7.2 - CIS Metric Filter for Root Account Usage
# description: A metric filter and alarm should exist for root account usage
# scope: package
package sigcomply.soc2.cc7_2_cis_root_account_usage

metadata := {
	"id": "soc2-cc7.2-cis-root-account-usage",
	"name": "CIS Alarm - Root Account Usage",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:cloudwatch:cis-metric-filter"],
	"remediation": "Create a CloudWatch metric filter for root account usage and associate an SNS alarm.",
}

violations contains violation if {
	input.resource_type == "aws:cloudwatch:cis-metric-filter"
	input.data.filter_name == "root_account_usage"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No metric filter and alarm configured for root account usage (CIS 4.3)",
		"details": {
			"cis_control": "4.3",
			"filter_name": "root_account_usage",
		},
	}
}
