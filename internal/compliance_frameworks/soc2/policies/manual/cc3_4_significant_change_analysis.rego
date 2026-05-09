# METADATA
# title: CC3.4 - Significant Change Impact Analysis
# description: Significant changes affecting internal controls must be analyzed each period
# scope: package
package sigcomply.soc2.cc3_4_significant_change_analysis

metadata := {
	"id": "soc2-cc3.4-significant-change-analysis",
	"name": "Significant Change Impact Analysis",
	"framework": "soc2",
	"control": "CC3.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:significant_change_analysis"],
	"category": "risk_compliance",
	"remediation": "Declare that significant changes were analyzed (or that none occurred) this period.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:significant_change_analysis"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Significant change analysis for period %s is overdue and not completed", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:significant_change_analysis"
	input.data.status == "uploaded"
	input.data.accepted != true
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Significant change analysis declaration was not accepted",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:significant_change_analysis"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Significant change analysis evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}
