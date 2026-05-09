# METADATA
# title: CC7.2 - GuardDuty Lambda Protection
# description: GuardDuty Lambda Protection must be enabled for serverless threat detection
# scope: package
package sigcomply.soc2.cc7_2_guardduty_lambda_protection

metadata := {
	"id": "soc2-cc7.2-guardduty-lambda-protection",
	"name": "GuardDuty Lambda Protection Enabled",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:guardduty:detector"],
	"remediation": "Enable GuardDuty Lambda Protection: aws guardduty update-detector --detector-id <id> --features [{Name=LAMBDA_NETWORK_LOGS,Status=ENABLED}]",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:guardduty:detector"
	input.data.enabled == true
	input.data.lambda_protection_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GuardDuty Lambda Protection is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
			"detector_id": input.data.detector_id,
		},
	}
}
