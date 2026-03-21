# METADATA
# title: CC7.2 - GuardDuty S3 Protection
# description: GuardDuty S3 Protection must be enabled for threat detection on S3 data events
# scope: package
package sigcomply.soc2.cc7_2_guardduty_s3_protection

metadata := {
	"id": "soc2-cc7.2-guardduty-s3-protection",
	"name": "GuardDuty S3 Protection Enabled",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:guardduty:detector"],
	"remediation": "Enable GuardDuty S3 Protection: aws guardduty update-detector --detector-id <id> --data-sources S3Logs={Enable=true}",
}

violations contains violation if {
	input.resource_type == "aws:guardduty:detector"
	input.data.enabled == true
	input.data.s3_protection_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GuardDuty S3 Protection is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
			"detector_id": input.data.detector_id,
		},
	}
}
