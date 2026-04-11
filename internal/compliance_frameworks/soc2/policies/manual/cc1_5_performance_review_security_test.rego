package sigcomply.soc2.cc1_5_performance_review_security_test

import data.sigcomply.soc2.cc1_5_performance_review_security

test_overdue_not_uploaded if {
	result := cc1_5_performance_review_security.violations with input as {
		"resource_type": "manual:performance_review_security",
		"resource_id": "performance_review_security/2026",
		"data": {
			"evidence_id": "performance_review_security",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_within_window_not_uploaded if {
	result := cc1_5_performance_review_security.violations with input as {
		"resource_type": "manual:performance_review_security",
		"resource_id": "performance_review_security/2026",
		"data": {
			"evidence_id": "performance_review_security",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

test_uploaded_verified if {
	result := cc1_5_performance_review_security.violations with input as {
		"resource_type": "manual:performance_review_security",
		"resource_id": "performance_review_security/2026",
		"data": {
			"evidence_id": "performance_review_security",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "reviews.pdf", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc1_5_performance_review_security.violations with input as {
		"resource_type": "manual:performance_review_security",
		"resource_id": "performance_review_security/2026",
		"data": {
			"evidence_id": "performance_review_security",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "reviews.pdf", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc1_5_performance_review_security.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
