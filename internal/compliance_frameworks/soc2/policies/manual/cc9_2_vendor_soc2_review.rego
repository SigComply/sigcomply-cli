# METADATA
# title: CC9.2 - Vendor SOC 2 Report Review
# description: Annual review of critical vendor SOC 2 reports must be completed
# scope: package
package sigcomply.soc2.cc9_2_vendor_soc2_review

metadata := {
	"id": "soc2-cc9.2-vendor-soc2-review",
	"name": "Vendor SOC 2 Report Review",
	"framework": "soc2",
	"control": "CC9.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:vendor_soc2_review"],
	"category": "risk_compliance",
	"remediation": "Complete the vendor SOC 2 review checklist with all required items.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:vendor_soc2_review"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Vendor SOC 2 Report Review for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
