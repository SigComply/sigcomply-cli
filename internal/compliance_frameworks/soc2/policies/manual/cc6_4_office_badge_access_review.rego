# METADATA
# title: CC6.4 - Office Badge Access Review
# description: Quarterly office badge access review must be uploaded
# scope: package
package sigcomply.soc2.cc6_4_office_badge_access_review

metadata := {
	"id": "soc2-cc6.4-office-badge-access-review",
	"name": "Office Badge Access Review",
	"framework": "soc2",
	"control": "CC6.4",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:office_badge_access_review"],
	"category": "access_physical",
	"remediation": "Upload the quarterly office badge access review showing active badge holders and access levels.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:office_badge_access_review"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Office Badge Access Review for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
