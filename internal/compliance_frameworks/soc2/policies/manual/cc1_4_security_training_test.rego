package sigcomply.soc2.cc1_4_security_training_test

import data.sigcomply.soc2.cc1_4_security_training

# Test: overdue and not uploaded
test_overdue_not_uploaded if {
	result := cc1_4_security_training.violations with input as {
		"resource_type": "manual:security_awareness_training",
		"resource_id": "security_awareness_training/2026",
		"data": {
			"evidence_id": "security_awareness_training",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

# Test: within window not uploaded should pass
test_within_window if {
	result := cc1_4_security_training.violations with input as {
		"resource_type": "manual:security_awareness_training",
		"resource_id": "security_awareness_training/2026",
		"data": {
			"evidence_id": "security_awareness_training",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

# Test: uploaded and verified should pass
test_uploaded_verified if {
	result := cc1_4_security_training.violations with input as {
		"resource_type": "manual:security_awareness_training",
		"resource_id": "security_awareness_training/2026",
		"data": {
			"evidence_id": "security_awareness_training",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "training.pdf", "sha256": "abc", "size_bytes": 500}],
		},
	}
	count(result) == 0
}

# Test: wrong resource type
test_wrong_resource_type if {
	result := cc1_4_security_training.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "some-arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
