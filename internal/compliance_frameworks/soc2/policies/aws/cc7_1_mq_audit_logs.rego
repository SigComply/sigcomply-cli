# METADATA
# title: CC7.1 - Amazon MQ Audit Logging
# description: Amazon MQ brokers must have audit logging enabled
# scope: package
package sigcomply.soc2.cc7_1_mq_audit_logs

metadata := {
	"id": "soc2-cc7.1-mq-audit-logs",
	"name": "Amazon MQ Audit Logging Enabled",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:mq:broker"],
	"remediation": "Enable audit logging for Amazon MQ brokers via the AWS Console or CLI: aws mq update-broker --broker-id <id> --logs Audit=true",
}

violations contains violation if {
	input.resource_type == "aws:mq:broker"
	input.data.audit_logs_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Amazon MQ broker '%s' does not have audit logging enabled", [input.data.broker_name]),
		"details": {"broker_name": input.data.broker_name},
	}
}
