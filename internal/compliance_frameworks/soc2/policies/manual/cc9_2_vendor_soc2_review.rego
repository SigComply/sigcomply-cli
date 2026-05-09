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
		"reason": sprintf("Vendor SOC 2 review for period %s is overdue and not completed", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:vendor_soc2_review"
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
	input.resource_type == "manual:vendor_soc2_review"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Vendor SOC 2 review evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}
