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
		"reason": sprintf("Quarterly Privacy Program Review for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
