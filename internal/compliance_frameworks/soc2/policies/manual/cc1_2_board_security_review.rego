# METADATA
# title: CC1.2 - Board Security Review Minutes
# description: Quarterly board review of information security posture must be documented
# scope: package
package sigcomply.soc2.cc1_2_board_security_review

metadata := {
	"id": "soc2-cc1.2-board-security-review",
	"name": "Board Security Review Minutes",
	"framework": "soc2",
	"control": "CC1.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:board_security_review"],
	"category": "hr_governance",
	"remediation": "Upload minutes of the quarterly board review of information security posture.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:board_security_review"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Board Security Review Minutes for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
