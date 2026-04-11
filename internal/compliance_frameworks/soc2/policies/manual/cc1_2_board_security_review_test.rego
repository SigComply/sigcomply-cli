package sigcomply.soc2.cc1_2_board_security_review_test

import data.sigcomply.soc2.cc1_2_board_security_review

test_overdue_not_uploaded if {
	result := cc1_2_board_security_review.violations with input as {
		"resource_type": "manual:board_security_review",
		"resource_id": "board_security_review/2026-Q1",
		"data": {
			"evidence_id": "board_security_review",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc1_2_board_security_review.violations with input as {
		"resource_type": "manual:board_security_review",
		"resource_id": "board_security_review/2026-Q1",
		"data": {
			"evidence_id": "board_security_review",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "minutes.pdf", "sha256": "abc", "size_bytes": 2048}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc1_2_board_security_review.violations with input as {
		"resource_type": "manual:board_security_review",
		"resource_id": "board_security_review/2026-Q1",
		"data": {
			"evidence_id": "board_security_review",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "minutes.pdf", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc1_2_board_security_review.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
