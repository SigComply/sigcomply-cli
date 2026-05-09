# METADATA
# title: A1.1 - Quarterly Capacity Review
# description: Quarterly capacity review report must be uploaded
# scope: package
package sigcomply.soc2.a1_1_capacity_review

metadata := {
	"id": "soc2-a1.1-capacity-review",
	"name": "Quarterly Capacity Review",
	"framework": "soc2",
	"control": "A1.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:capacity_review"],
	"category": "system_ops_bcdr",
	"remediation": "Upload the quarterly capacity review report.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:capacity_review"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Quarterly Capacity Review for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
