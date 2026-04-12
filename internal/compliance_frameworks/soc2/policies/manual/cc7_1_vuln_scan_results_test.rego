package sigcomply.soc2.cc7_1_vuln_scan_results_test

import data.sigcomply.soc2.cc7_1_vuln_scan_results

test_overdue if {
	result := cc7_1_vuln_scan_results.violations with input as {
		"resource_type": "manual:vuln_scan_results",
		"resource_id": "vuln_scan_results/2026-Q1",
		"data": {
			"evidence_id": "vuln_scan_results",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc7_1_vuln_scan_results.violations with input as {
		"resource_type": "manual:vuln_scan_results",
		"resource_id": "vuln_scan_results/2026-Q1",
		"data": {
			"evidence_id": "vuln_scan_results",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "scan.pdf", "sha256": "abc", "size_bytes": 4096}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc7_1_vuln_scan_results.violations with input as {
		"resource_type": "manual:vuln_scan_results",
		"resource_id": "vuln_scan_results/2026-Q1",
		"data": {
			"evidence_id": "vuln_scan_results",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "scan.pdf", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc7_1_vuln_scan_results.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
