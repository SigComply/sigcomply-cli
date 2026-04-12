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
}

violations contains violation if {
	input.resource_type == "manual:business_continuity_plan"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Business continuity plan for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:business_continuity_plan"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Business continuity plan evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:business_continuity_plan"
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
