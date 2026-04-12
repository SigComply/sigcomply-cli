package sigcomply.soc2.cc8_1_change_approval_log_test

import data.sigcomply.soc2.cc8_1_change_approval_log

test_overdue if {
	result := cc8_1_change_approval_log.violations with input as {
		"resource_type": "manual:change_approval_log",
		"resource_id": "change_approval_log/2026-Q1",
		"data": {
			"evidence_id": "change_approval_log",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc8_1_change_approval_log.violations with input as {
		"resource_type": "manual:change_approval_log",
		"resource_id": "change_approval_log/2026-Q1",
		"data": {
			"evidence_id": "change_approval_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "changes.xlsx", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc8_1_change_approval_log.violations with input as {
		"resource_type": "manual:change_approval_log",
		"resource_id": "change_approval_log/2026-Q1",
		"data": {
			"evidence_id": "change_approval_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "changes.xlsx", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc8_1_change_approval_log.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
