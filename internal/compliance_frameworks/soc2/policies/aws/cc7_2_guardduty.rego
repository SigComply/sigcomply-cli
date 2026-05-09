# METADATA
# title: CC7.2 - Threat Detection
# description: GuardDuty must be enabled for threat detection
# scope: package
package sigcomply.soc2.cc7_2_guardduty

metadata := {
	"id": "soc2-cc7.2-guardduty",
	"name": "Threat Detection Enabled",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:guardduty:detector"],
	"remediation": "Enable Amazon GuardDuty: aws guardduty create-detector --enable",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:guardduty:detector"
	input.data.enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GuardDuty is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
		},
	}
}
