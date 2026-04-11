package sigcomply.soc2.a1_3_dr_test_report_test

import data.sigcomply.soc2.a1_3_dr_test_report

test_overdue if {
	result := a1_3_dr_test_report.violations with input as {
		"resource_type": "manual:dr_test_report",
		"resource_id": "dr_test_report/2026",
		"data": {
			"evidence_id": "dr_test_report",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := a1_3_dr_test_report.violations with input as {
		"resource_type": "manual:dr_test_report",
		"resource_id": "dr_test_report/2026",
		"data": {
			"evidence_id": "dr_test_report",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "dr.pdf", "sha256": "abc", "size_bytes": 2048}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := a1_3_dr_test_report.violations with input as {
		"resource_type": "manual:dr_test_report",
		"resource_id": "dr_test_report/2026",
		"data": {
			"evidence_id": "dr_test_report",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "dr.pdf", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := a1_3_dr_test_report.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
