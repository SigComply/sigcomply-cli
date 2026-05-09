# METADATA
# title: CC7.1 - Vulnerability Remediation Tracker
# description: Quarterly vulnerability remediation tracker must be uploaded
# scope: package
package sigcomply.soc2.cc7_1_vuln_remediation_tracker

metadata := {
	"id": "soc2-cc7.1-vuln-remediation-tracker",
	"name": "Vulnerability Remediation Tracker",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:vuln_remediation_tracker"],
	"category": "vulnerability_management",
	"remediation": "Upload the quarterly vulnerability remediation tracker showing open/closed vulnerabilities and remediation timelines.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:vuln_remediation_tracker"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Vulnerability remediation tracker for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:vuln_remediation_tracker"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Vulnerability remediation tracker evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:vuln_remediation_tracker"
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
