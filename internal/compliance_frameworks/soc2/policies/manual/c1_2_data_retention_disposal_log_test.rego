package sigcomply.soc2.c1_2_data_retention_disposal_log_test

import data.sigcomply.soc2.c1_2_data_retention_disposal_log

test_overdue if {
	result := c1_2_data_retention_disposal_log.violations with input as {
		"resource_type": "manual:data_retention_disposal_log",
		"resource_id": "data_retention_disposal_log/2026-Q1",
		"data": {
			"evidence_id": "data_retention_disposal_log",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := c1_2_data_retention_disposal_log.violations with input as {
		"resource_type": "manual:data_retention_disposal_log",
		"resource_id": "data_retention_disposal_log/2026-Q1",
		"data": {
			"evidence_id": "data_retention_disposal_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "retention.csv", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := c1_2_data_retention_disposal_log.violations with input as {
		"resource_type": "manual:data_retention_disposal_log",
		"resource_id": "data_retention_disposal_log/2026-Q1",
		"data": {
			"evidence_id": "data_retention_disposal_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "retention.csv", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := c1_2_data_retention_disposal_log.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
