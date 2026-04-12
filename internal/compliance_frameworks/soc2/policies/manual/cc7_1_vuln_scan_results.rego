# METADATA
# title: CC7.1 - Vulnerability Scan Results
# description: Quarterly vulnerability scan results must be uploaded
# scope: package
package sigcomply.soc2.cc7_1_vuln_scan_results

metadata := {
	"id": "soc2-cc7.1-vuln-scan-results",
	"name": "Vulnerability Scan Results",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:vuln_scan_results"],
	"category": "vulnerability_management",
	"remediation": "Upload the quarterly vulnerability scan results from internal or external scanning tools.",
}

violations contains violation if {
	input.resource_type == "manual:vuln_scan_results"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Vulnerability scan results for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:vuln_scan_results"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "Vulnerability scan results evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:vuln_scan_results"
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
