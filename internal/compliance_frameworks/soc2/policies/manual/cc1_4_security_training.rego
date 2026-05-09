# METADATA
# title: CC1.4 - Security Awareness Training
# description: Annual security awareness training must be completed for all employees
# scope: package
package sigcomply.soc2.cc1_4_security_training

metadata := {
	"id": "soc2-cc1.4-security-training",
	"name": "Security Awareness Training",
	"framework": "soc2",
	"control": "CC1.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:security_awareness_training"],
	"category": "configuration_management",
	"remediation": "Upload evidence of annual security awareness training completion.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:security_awareness_training"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Security Awareness Training for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
