package sigcomply.soc2.c1_1_data_classification_registry_test

import data.sigcomply.soc2.c1_1_data_classification_registry

test_overdue if {
	result := c1_1_data_classification_registry.violations with input as {
		"resource_type": "manual:data_classification_registry",
		"resource_id": "data_classification_registry/2026",
		"data": {
			"evidence_id": "data_classification_registry",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := c1_1_data_classification_registry.violations with input as {
		"resource_type": "manual:data_classification_registry",
		"resource_id": "data_classification_registry/2026",
		"data": {
			"evidence_id": "data_classification_registry",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "registry.xlsx", "sha256": "abc", "size_bytes": 8192}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := c1_1_data_classification_registry.violations with input as {
		"resource_type": "manual:data_classification_registry",
		"resource_id": "data_classification_registry/2026",
		"data": {
			"evidence_id": "data_classification_registry",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "registry.xlsx", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := c1_1_data_classification_registry.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
