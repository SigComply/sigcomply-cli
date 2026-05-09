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
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:change_approval_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Change Approval Log for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
