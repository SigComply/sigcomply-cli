# METADATA
# title: CC6.3 - Quarterly Access Review
# description: Quarterly user access review must be completed with valid documentation
# scope: package
package sigcomply.soc2.cc6_3_quarterly_access_review

metadata := {
	"id": "soc2-cc6.3-quarterly-access-review",
	"name": "Quarterly Access Review",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:quarterly_access_review"],
	"category": "access_control",
	"remediation": "Complete the quarterly access review by uploading a signed access review document.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:quarterly_access_review"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Quarterly Access Review for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
