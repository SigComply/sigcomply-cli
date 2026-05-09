package sigcomply.soc2.c1_1_data_classification_registry_test

import data.sigcomply.soc2.c1_1_data_classification_registry

# Overdue + not_uploaded → one violation
test_overdue_not_uploaded if {
	result := c1_1_data_classification_registry.violations with input as {
		"resource_type": "manual:data_classification_registry",
		"resource_id": "data_classification_registry/2026-Q1",
		"data": {
			"evidence_id": "data_classification_registry",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

# Uploaded within window → no violation
test_uploaded_within_window if {
	result := c1_1_data_classification_registry.violations with input as {
		"resource_type": "manual:data_classification_registry",
		"resource_id": "data_classification_registry/2026-Q1",
		"data": {
			"evidence_id": "data_classification_registry",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"file_hash": "abc123",
			"file_path": "soc2/data_classification_registry/2026-Q1/evidence.pdf",
		},
	}
	count(result) == 0
}

# Not-uploaded but within window → no violation (still in grace)
test_within_window_not_uploaded if {
	result := c1_1_data_classification_registry.violations with input as {
		"resource_type": "manual:data_classification_registry",
		"resource_id": "data_classification_registry/2026-Q1",
		"data": {
			"evidence_id": "data_classification_registry",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

# Wrong resource_type → no violation
test_wrong_resource_type if {
	result := c1_1_data_classification_registry.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/x",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
