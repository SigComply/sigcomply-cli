# METADATA
# title: CC7.2 - GuardDuty RDS Protection
# description: GuardDuty RDS Protection must be enabled for database threat detection
# scope: package
package sigcomply.soc2.cc7_2_guardduty_rds_protection

metadata := {
	"id": "soc2-cc7.2-guardduty-rds-protection",
	"name": "GuardDuty RDS Protection Enabled",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:guardduty:detector"],
	"remediation": "Enable GuardDuty RDS Protection: aws guardduty update-detector --detector-id <id> --features [{Name=RDS_LOGIN_EVENTS,Status=ENABLED}]",
}

violations contains violation if {
	input.resource_type == "aws:guardduty:detector"
	input.data.enabled == true
	input.data.rds_protection_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GuardDuty RDS Protection is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
			"detector_id": input.data.detector_id,
		},
	}
}
