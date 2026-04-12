package sigcomply.soc2.cc5_3_policy_review_log_test

import data.sigcomply.soc2.cc5_3_policy_review_log

test_overdue if {
	result := cc5_3_policy_review_log.violations with input as {
		"resource_type": "manual:policy_review_log",
		"resource_id": "policy_review_log/2026",
		"data": {
			"evidence_id": "policy_review_log",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc5_3_policy_review_log.violations with input as {
		"resource_type": "manual:policy_review_log",
		"resource_id": "policy_review_log/2026",
		"data": {
			"evidence_id": "policy_review_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "policies.pdf", "sha256": "abc", "size_bytes": 2048}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc5_3_policy_review_log.violations with input as {
		"resource_type": "manual:policy_review_log",
		"resource_id": "policy_review_log/2026",
		"data": {
			"evidence_id": "policy_review_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "policies.pdf", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc5_3_policy_review_log.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
