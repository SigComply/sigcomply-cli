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
}

violations contains violation if {
	input.resource_type == "manual:office_badge_access_review"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Office badge access review for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:office_badge_access_review"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Office badge access review evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:office_badge_access_review"
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
