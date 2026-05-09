# METADATA
# title: CC7.2 - GuardDuty Alerting Configured
# description: EventBridge must have rules to alert on GuardDuty findings
# scope: package
package sigcomply.soc2.cc7_2_guardduty_alerting

metadata := {
	"id": "soc2-cc7.2-guardduty-alerting",
	"name": "GuardDuty Alerting Configured",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:eventbridge:guardduty-alert"],
	"remediation": "Create an EventBridge rule for GuardDuty findings with an SNS target for alerting.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:eventbridge:guardduty-alert"
	input.data.has_guardduty_rule == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("No EventBridge rule configured for GuardDuty findings in region '%s'. Configure alerting for security findings.", [input.data.region]),
		"details": {
			"region": input.data.region,
		},
	}
}
