package sigcomply.soc2.cc7_1_fim_configuration_test

import data.sigcomply.soc2.cc7_1_fim_configuration

test_overdue if {
	result := cc7_1_fim_configuration.violations with input as {
		"resource_type": "manual:fim_configuration",
		"resource_id": "fim_configuration/2026",
		"data": {
			"evidence_id": "fim_configuration",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc7_1_fim_configuration.violations with input as {
		"resource_type": "manual:fim_configuration",
		"resource_id": "fim_configuration/2026",
		"data": {
			"evidence_id": "fim_configuration",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "fim-config.pdf", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_hash_failure if {
	result := cc7_1_fim_configuration.violations with input as {
		"resource_type": "manual:fim_configuration",
		"resource_id": "fim_configuration/2026",
		"data": {
			"evidence_id": "fim_configuration",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": false,
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc7_1_fim_configuration.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
