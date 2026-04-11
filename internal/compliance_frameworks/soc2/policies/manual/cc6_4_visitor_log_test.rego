package sigcomply.soc2.cc6_4_visitor_log_test

import data.sigcomply.soc2.cc6_4_visitor_log

test_overdue if {
	result := cc6_4_visitor_log.violations with input as {
		"resource_type": "manual:visitor_log",
		"resource_id": "visitor_log/2026-Q1",
		"data": {
			"evidence_id": "visitor_log",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc6_4_visitor_log.violations with input as {
		"resource_type": "manual:visitor_log",
		"resource_id": "visitor_log/2026-Q1",
		"data": {
			"evidence_id": "visitor_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "visitors.csv", "sha256": "abc", "size_bytes": 512}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc6_4_visitor_log.violations with input as {
		"resource_type": "manual:visitor_log",
		"resource_id": "visitor_log/2026-Q1",
		"data": {
			"evidence_id": "visitor_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "visitors.csv", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_4_visitor_log.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
