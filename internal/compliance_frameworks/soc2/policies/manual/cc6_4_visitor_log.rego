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
}

violations contains violation if {
	input.resource_type == "manual:visitor_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Visitor log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:visitor_log"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Visitor log evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:visitor_log"
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
