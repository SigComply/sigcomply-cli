# METADATA
# title: CC9.2 - Vendor Risk Directory Snapshot
# description: Quarterly vendor risk directory snapshot must be uploaded
# scope: package
package sigcomply.soc2.cc9_2_vendor_risk_directory

metadata := {
	"id": "soc2-cc9.2-vendor-risk-directory",
	"name": "Vendor Risk Directory Snapshot",
	"framework": "soc2",
	"control": "CC9.2",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:vendor_risk_directory"],
	"category": "risk_compliance",
	"remediation": "Upload the quarterly vendor risk directory snapshot listing all active vendors, data classification, and risk tier.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:vendor_risk_directory"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Vendor Risk Directory Snapshot for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}
