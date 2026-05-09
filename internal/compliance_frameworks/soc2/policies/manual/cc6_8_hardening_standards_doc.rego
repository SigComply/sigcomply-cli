# METADATA
# title: CC6.8 - Hardening Standards Document
# description: Annual hardening standards document must be uploaded
# scope: package
package sigcomply.soc2.cc6_8_hardening_standards_doc

metadata := {
	"id": "soc2-cc6.8-hardening-standards-doc",
	"name": "Hardening Standards Document",
	"framework": "soc2",
	"control": "CC6.8",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:hardening_standards_doc"],
	"category": "vulnerability_management",
	"remediation": "Upload the current hardening standards document covering OS, database, and application baseline configurations.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:hardening_standards_doc"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Hardening Standards Document for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
