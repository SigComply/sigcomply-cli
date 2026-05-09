# METADATA
# title: CC6.1 - Privileged Access Justification Log
# description: Quarterly log of privileged access grants with justifications must be uploaded
# scope: package
package sigcomply.soc2.cc6_1_privileged_access_log

metadata := {
	"id": "soc2-cc6.1-privileged-access-log",
	"name": "Privileged Access Justification Log",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:privileged_access_log"],
	"category": "access_physical",
	"remediation": "Upload the quarterly privileged access log with business justifications.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:privileged_access_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Privileged access log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:privileged_access_log"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Privileged access log evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:privileged_access_log"
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
