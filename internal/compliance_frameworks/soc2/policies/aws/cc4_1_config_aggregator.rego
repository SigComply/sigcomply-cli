# METADATA
# title: CC4.1 - AWS Config Aggregator
# description: AWS Config should have a multi-account aggregator for centralized compliance monitoring
# scope: package
package sigcomply.soc2.cc4_1_config_aggregator

metadata := {
	"id": "soc2-cc4.1-config-aggregator",
	"name": "AWS Config Multi-Account Aggregator",
	"framework": "soc2",
	"control": "CC4.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:config:aggregator"],
	"remediation": "Create an AWS Config aggregator to centralize configuration data across accounts and regions: aws configservice put-configuration-aggregator",
}

violations contains violation if {
	input.resource_type == "aws:config:aggregator"
	input.data.configured == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "No AWS Config aggregator configured for multi-account/multi-region compliance monitoring",
		"details": {},
	}
}
