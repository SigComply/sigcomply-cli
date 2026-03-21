# METADATA
# title: CC7.2 - GuardDuty Runtime Monitoring
# description: GuardDuty Runtime Monitoring must be enabled for EC2/ECS/EKS runtime threat detection
# scope: package
package sigcomply.soc2.cc7_2_guardduty_runtime_monitoring

metadata := {
	"id": "soc2-cc7.2-guardduty-runtime-monitoring",
	"name": "GuardDuty Runtime Monitoring Enabled",
	"framework": "soc2",
	"control": "CC7.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:guardduty:detector"],
	"remediation": "Enable GuardDuty Runtime Monitoring: aws guardduty update-detector --detector-id <id> --features [{Name=RUNTIME_MONITORING,Status=ENABLED}]",
}

violations contains violation if {
	input.resource_type == "aws:guardduty:detector"
	input.data.enabled == true
	input.data.runtime_monitoring_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("GuardDuty Runtime Monitoring is not enabled in region '%s'", [input.data.region]),
		"details": {
			"region": input.data.region,
			"detector_id": input.data.detector_id,
		},
	}
}
