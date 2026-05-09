# METADATA
# title: CC6.4 - Office Security Walkthrough
# description: Quarterly office security walkthrough checklist must be completed
# scope: package
package sigcomply.soc2.cc6_4_office_walkthrough

metadata := {
	"id": "soc2-cc6.4-office-walkthrough",
	"name": "Office Security Walkthrough",
	"framework": "soc2",
	"control": "CC6.4",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:office_walkthrough"],
	"category": "access_physical",
	"remediation": "Complete the office security walkthrough checklist with all required items.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:office_walkthrough"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Office Security Walkthrough for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
