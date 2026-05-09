# METADATA
# title: P5.2 - DSAR Fulfillment Log
# description: Quarterly DSAR fulfillment log must be uploaded
# scope: package
package sigcomply.soc2.p5_2_dsar_fulfillment_log

metadata := {
	"id": "soc2-p5.2-dsar-fulfillment-log",
	"name": "DSAR Fulfillment Log",
	"framework": "soc2",
	"control": "P5.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:dsar_fulfillment_log"],
	"category": "privacy",
	"remediation": "Upload the quarterly DSAR fulfillment log showing all data subject requests received and their resolution status.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:dsar_fulfillment_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DSAR Fulfillment Log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
