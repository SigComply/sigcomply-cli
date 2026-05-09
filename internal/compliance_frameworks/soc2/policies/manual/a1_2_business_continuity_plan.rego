# METADATA
# title: A1.2 - Business Continuity Plan
# description: Annual business continuity plan must be uploaded
# scope: package
package sigcomply.soc2.a1_2_business_continuity_plan

metadata := {
	"id": "soc2-a1.2-business-continuity-plan",
	"name": "Business Continuity Plan",
	"framework": "soc2",
	"control": "A1.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:business_continuity_plan"],
	"category": "system_ops_bcdr",
	"remediation": "Upload the current business continuity plan documenting recovery procedures and business impact analysis.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:business_continuity_plan"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Business Continuity Plan for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
