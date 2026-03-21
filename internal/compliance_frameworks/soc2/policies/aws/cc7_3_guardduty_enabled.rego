# METADATA
# title: CC7.3 - GuardDuty Enabled
# description: GuardDuty should be enabled for security event detection and evaluation
# scope: package
package sigcomply.soc2.cc7_3_guardduty_enabled

metadata := {
	"id": "soc2-cc7.3-guardduty-enabled",
	"name": "GuardDuty Enabled for Event Evaluation",
	"framework": "soc2",
	"control": "CC7.3",
	"severity": "critical",
	"evaluation_mode": "individual",
	"resource_types": ["aws:guardduty:detector"],
	"remediation": "Enable GuardDuty in the AWS account for threat detection.",
}

violations contains violation if {
	input.resource_type == "aws:guardduty:detector"
	input.data.enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GuardDuty is not enabled in region %s for security event evaluation", [input.data.region]),
		"details": {"region": input.data.region},
	}
}
