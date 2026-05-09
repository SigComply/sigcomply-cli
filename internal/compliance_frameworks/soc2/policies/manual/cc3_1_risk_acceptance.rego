# METADATA
# title: CC3.1 - Risk Acceptance Sign-off
# description: Quarterly risk acceptance must be declared and accepted by management
# scope: package
package sigcomply.soc2.cc3_1_risk_acceptance

metadata := {
	"id": "soc2-cc3.1-risk-acceptance",
	"name": "Risk Acceptance Sign-off",
	"framework": "soc2",
	"control": "CC3.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:risk_acceptance_signoff"],
	"category": "vulnerability_management",
	"remediation": "Complete the risk acceptance declaration and confirm acceptance.",
	"evidence_type": "manual",
}

# Violation: not uploaded and overdue
violations contains violation if {
	input.resource_type == "manual:risk_acceptance_signoff"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Risk acceptance sign-off for period %s is overdue and not completed", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

# Violation: declaration not accepted
violations contains violation if {
	input.resource_type == "manual:risk_acceptance_signoff"
	input.data.status == "uploaded"
	input.data.accepted != true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Risk acceptance declaration was not accepted",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

# Violation: hash verification failed
violations contains violation if {
	input.resource_type == "manual:risk_acceptance_signoff"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Risk acceptance evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}
