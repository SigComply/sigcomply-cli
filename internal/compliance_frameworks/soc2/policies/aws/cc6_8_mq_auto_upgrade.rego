# METADATA
# title: CC6.8 - Amazon MQ Auto Minor Version Upgrade
# description: Amazon MQ brokers must have automatic minor version upgrades enabled to receive security patches
# scope: package
package sigcomply.soc2.cc6_8_mq_auto_upgrade

metadata := {
	"id": "soc2-cc6.8-mq-auto-upgrade",
	"name": "Amazon MQ Auto Minor Version Upgrade Enabled",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:mq:broker"],
	"remediation": "Enable automatic minor version upgrades for Amazon MQ brokers via the AWS Console or CLI: aws mq update-broker --broker-id <id> --auto-minor-version-upgrade",
}

violations contains violation if {
	input.resource_type == "aws:mq:broker"
	input.data.auto_minor_version_upgrade == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Amazon MQ broker '%s' does not have automatic minor version upgrades enabled", [input.data.broker_name]),
		"details": {"broker_name": input.data.broker_name},
	}
}
