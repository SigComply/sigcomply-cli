# METADATA
# title: CC5.3 - Annual Policy Review Log
# description: Annual log of policy reviews and updates must be uploaded
# scope: package
package sigcomply.soc2.cc5_3_policy_review_log

metadata := {
	"id": "soc2-cc5.3-policy-review-log",
	"name": "Annual Policy Review Log",
	"framework": "soc2",
	"control": "CC5.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:policy_review_log"],
	"category": "risk_compliance",
	"remediation": "Upload the annual policy review log showing each information security policy was reviewed and (if needed) updated.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:policy_review_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Annual policy review log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:policy_review_log"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Policy review log evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:policy_review_log"
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
