# METADATA
# title: CC8.1 - Change Approval Log
# description: Quarterly change approval log must be uploaded
# scope: package
package sigcomply.soc2.cc8_1_change_approval_log

metadata := {
	"id": "soc2-cc8.1-change-approval-log",
	"name": "Change Approval Log",
	"framework": "soc2",
	"control": "CC8.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:change_approval_log"],
	"category": "change_management",
	"remediation": "Upload the quarterly change approval log showing all production changes with approver sign-off.",
}

violations contains violation if {
	input.resource_type == "manual:change_approval_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Change approval log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:change_approval_log"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Change approval log evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:change_approval_log"
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
