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
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:vuln_scan_results"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Vulnerability Scan Results for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
