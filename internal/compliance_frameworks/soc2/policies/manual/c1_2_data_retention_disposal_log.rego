# METADATA
# title: C1.2 - Data Retention & Disposal Log
# description: Quarterly data retention and disposal log must be uploaded
# scope: package
package sigcomply.soc2.c1_2_data_retention_disposal_log

metadata := {
	"id": "soc2-c1.2-data-retention-disposal-log",
	"name": "Data Retention & Disposal Log",
	"framework": "soc2",
	"control": "C1.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["manual:data_retention_disposal_log"],
	"category": "data_protection",
	"remediation": "Upload the quarterly data retention and disposal log showing data disposed per the retention schedule.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:data_retention_disposal_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Data Retention & Disposal Log for period %s is overdue and not uploaded. Expected at: %s", [input.data.period, input.data.expected_uri]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
