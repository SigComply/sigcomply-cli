# METADATA
# title: CC8.1 - Config Change Tracking
# description: AWS Config must be enabled for configuration change tracking
# scope: package
package sigcomply.soc2.cc8_1_config

metadata := {
	"id": "soc2-cc8.1-config-enabled",
	"name": "Config Change Tracking",
	"framework": "soc2",
	"control": "CC8.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:config:recorder"],
	"remediation": "Enable AWS Config recorder: aws configservice put-configuration-recorder",
}

violations contains violation if {
	input.resource_type == "aws:config:recorder"
	input.data.enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("AWS Config is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
		},
	}
}
