# METADATA
# title: CC3.3 - Fraud Risk Assessment
# description: Annual fraud risk assessment report must be uploaded
# scope: package
package sigcomply.soc2.cc3_3_fraud_risk_assessment

metadata := {
	"id": "soc2-cc3.3-fraud-risk-assessment",
	"name": "Fraud Risk Assessment",
	"framework": "soc2",
	"control": "CC3.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:fraud_risk_assessment"],
	"category": "risk_compliance",
	"remediation": "Upload the annual fraud risk assessment covering potential fraud scenarios and mitigating controls.",
}

violations contains violation if {
	input.resource_type == "manual:fraud_risk_assessment"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Fraud risk assessment for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:fraud_risk_assessment"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Fraud risk assessment evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:fraud_risk_assessment"
	input.data.status == "uploaded"
	input.data.files[i].error
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Attachment '%s' not found in storage", [input.data.files[i].name]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"file": input.data.files[i].name,
		},
	}
}
