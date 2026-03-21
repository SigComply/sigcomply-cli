# METADATA
# title: CC7.1 - SNS Delivery Logging
# description: SNS topics should have delivery status logging enabled
# scope: package
package sigcomply.soc2.cc7_1_sns_delivery_logging

metadata := {
	"id": "soc2-cc7.1-sns-delivery-logging",
	"name": "SNS Delivery Logging",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:sns:topic"],
	"remediation": "Enable delivery status logging for the SNS topic.",
}

violations contains violation if {
	input.resource_type == "aws:sns:topic"
	input.data.delivery_logging_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("SNS topic '%s' does not have delivery status logging enabled", [input.data.name]),
		"details": {"topic_name": input.data.name},
	}
}
