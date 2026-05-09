# METADATA
# title: P1.1 - Quarterly Privacy Program Review
# description: Quarterly privacy program review checklist must be completed
# scope: package
package sigcomply.soc2.p1_1_quarterly_privacy_review

metadata := {
	"id": "soc2-p1.1-quarterly-privacy-review",
	"name": "Quarterly Privacy Program Review",
	"framework": "soc2",
	"control": "P1.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:quarterly_privacy_review"],
	"category": "privacy",
	"remediation": "Complete the quarterly privacy program review checklist covering notice, DSARs, consent, and data minimization.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:quarterly_privacy_review"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Quarterly privacy program review for period %s is overdue and not completed", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:quarterly_privacy_review"
	input.data.status == "uploaded"
	item := input.data.items[_]
	item.required == true
	item.checked == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Required checklist item '%s' is not checked", [item.text]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"item_id": item.id,
			"item_text": item.text,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:quarterly_privacy_review"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Privacy program review evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}
