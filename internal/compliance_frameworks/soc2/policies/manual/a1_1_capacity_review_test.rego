package sigcomply.soc2.a1_1_capacity_review_test

import data.sigcomply.soc2.a1_1_capacity_review

test_overdue if {
	result := a1_1_capacity_review.violations with input as {
		"resource_type": "manual:capacity_review",
		"resource_id": "capacity_review/2026-Q1",
		"data": {
			"evidence_id": "capacity_review",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := a1_1_capacity_review.violations with input as {
		"resource_type": "manual:capacity_review",
		"resource_id": "capacity_review/2026-Q1",
		"data": {
			"evidence_id": "capacity_review",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "capacity.xlsx", "sha256": "abc", "size_bytes": 4096}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := a1_1_capacity_review.violations with input as {
		"resource_type": "manual:capacity_review",
		"resource_id": "capacity_review/2026-Q1",
		"data": {
			"evidence_id": "capacity_review",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "capacity.xlsx", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := a1_1_capacity_review.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
