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
		"reason": sprintf("Vulnerability Remediation Tracker for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
