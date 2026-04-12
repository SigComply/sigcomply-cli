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
}

violations contains violation if {
	input.resource_type == "manual:dsar_fulfillment_log"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DSAR fulfillment log for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:dsar_fulfillment_log"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "DSAR fulfillment log evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:dsar_fulfillment_log"
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
