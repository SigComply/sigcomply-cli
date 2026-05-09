# METADATA
# title: CC6.4 - Physical Office Visitor Log
# description: Quarterly physical office visitor log must be uploaded
# scope: package
package sigcomply.soc2.cc6_4_visitor_log

metadata := {
	"id": "soc2-cc6.4-visitor-log",
	"name": "Physical Office Visitor Log",
	"framework": "soc2",
	"control": "CC6.4",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:visitor_log"],
	"category": "access_physical",
	"remediation": "Upload the quarterly physical office visitor log snapshot.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:visitor_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Physical Office Visitor Log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
