# METADATA
# title: CC9.1 - Cyber Liability Insurance Certificate
# description: Current cyber liability insurance certificate must be on file
# scope: package
package sigcomply.soc2.cc9_1_cyber_liability_insurance

metadata := {
	"id": "soc2-cc9.1-cyber-liability-insurance",
	"name": "Cyber Liability Insurance Certificate",
	"framework": "soc2",
	"control": "CC9.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:cyber_liability_insurance"],
	"category": "risk_compliance",
	"remediation": "Upload the current cyber liability insurance certificate.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:cyber_liability_insurance"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Cyber Liability Insurance Certificate for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
