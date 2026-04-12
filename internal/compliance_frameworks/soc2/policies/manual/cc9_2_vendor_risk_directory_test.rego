package sigcomply.soc2.cc9_2_vendor_risk_directory_test

import data.sigcomply.soc2.cc9_2_vendor_risk_directory

test_overdue if {
	result := cc9_2_vendor_risk_directory.violations with input as {
		"resource_type": "manual:vendor_risk_directory",
		"resource_id": "vendor_risk_directory/2026-Q1",
		"data": {
			"evidence_id": "vendor_risk_directory",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc9_2_vendor_risk_directory.violations with input as {
		"resource_type": "manual:vendor_risk_directory",
		"resource_id": "vendor_risk_directory/2026-Q1",
		"data": {
			"evidence_id": "vendor_risk_directory",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "vendors.xlsx", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc9_2_vendor_risk_directory.violations with input as {
		"resource_type": "manual:vendor_risk_directory",
		"resource_id": "vendor_risk_directory/2026-Q1",
		"data": {
			"evidence_id": "vendor_risk_directory",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "vendors.xlsx", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc9_2_vendor_risk_directory.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
