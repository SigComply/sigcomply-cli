# METADATA
# title: A1.2 - MQ Broker Multi-AZ
# description: Amazon MQ brokers should use multi-AZ deployment for high availability
# scope: package
package sigcomply.soc2.a1_2_mq_multi_az

metadata := {
	"id": "soc2-a1.2-mq-multi-az",
	"name": "MQ Broker Multi-AZ",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:mq:broker"],
	"remediation": "Configure the MQ broker with ACTIVE_STANDBY_MULTI_AZ deployment mode.",
}

violations contains violation if {
	input.resource_type == "aws:mq:broker"
	input.data.deployment_mode != "ACTIVE_STANDBY_MULTI_AZ"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("MQ broker '%s' is not configured for multi-AZ deployment", [input.data.broker_name]),
		"details": {"broker_name": input.data.broker_name, "deployment_mode": input.data.deployment_mode},
	}
}
