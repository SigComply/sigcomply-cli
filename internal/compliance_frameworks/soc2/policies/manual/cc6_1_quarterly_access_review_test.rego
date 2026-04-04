package sigcomply.soc2.cc6_1_quarterly_access_review_test

import data.sigcomply.soc2.cc6_1_quarterly_access_review

# Test: overdue and not uploaded should violate
test_overdue_not_uploaded if {
	result := cc6_1_quarterly_access_review.violations with input as {
		"resource_type": "manual:quarterly_access_review",
		"resource_id": "quarterly_access_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_access_review",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

# Test: not uploaded but within window should pass
test_within_window_not_uploaded if {
	result := cc6_1_quarterly_access_review.violations with input as {
		"resource_type": "manual:quarterly_access_review",
		"resource_id": "quarterly_access_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_access_review",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

# Test: uploaded and verified should pass
test_uploaded_verified if {
	result := cc6_1_quarterly_access_review.violations with input as {
		"resource_type": "manual:quarterly_access_review",
		"resource_id": "quarterly_access_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_access_review",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "report.pdf", "sha256": "abc123", "size_bytes": 1000}],
		},
	}
	count(result) == 0
}

# Test: uploaded but hash verification failed should violate
test_hash_failed if {
	result := cc6_1_quarterly_access_review.violations with input as {
		"resource_type": "manual:quarterly_access_review",
		"resource_id": "quarterly_access_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_access_review",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": false,
			"files": [{"name": "report.pdf", "error": "not_found"}],
		},
	}
	count(result) >= 1
}

# Test: wrong resource type should not match
test_wrong_resource_type if {
	result := cc6_1_quarterly_access_review.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}

# Test: missing attachment should violate
test_missing_attachment if {
	result := cc6_1_quarterly_access_review.violations with input as {
		"resource_type": "manual:quarterly_access_review",
		"resource_id": "quarterly_access_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_access_review",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "report.pdf", "error": "not_found"}],
		},
	}
	count(result) == 1
}
