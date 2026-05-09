# METADATA
# title: A1.3 - Disaster Recovery Test Report
# description: Annual disaster recovery test report must be uploaded
# scope: package
package sigcomply.soc2.a1_3_dr_test_report

metadata := {
	"id": "soc2-a1.3-dr-test-report",
	"name": "Disaster Recovery Test Report",
	"framework": "soc2",
	"control": "A1.3",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["manual:dr_test_report"],
	"category": "system_ops_bcdr",
	"remediation": "Upload the annual disaster recovery test report.",
	"evidence_type": "manual",
}

violations contains violation if {
	input.resource_type == "manual:dr_test_report"
	input.data.status == "not_uploaded"
	input.data.temporal_status == "overdue"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DR test report for period %s is overdue and not uploaded", [input.data.period]),
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
			"temporal_status": input.data.temporal_status,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:dr_test_report"
	input.data.status == "uploaded"
	input.data.hash_verified == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": "DR test report evidence failed integrity verification",
		"details": {
			"evidence_id": input.data.evidence_id,
			"period": input.data.period,
		},
	}
}

violations contains violation if {
	input.resource_type == "manual:dr_test_report"
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
