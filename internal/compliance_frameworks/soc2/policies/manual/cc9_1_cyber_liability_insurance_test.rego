package sigcomply.soc2.cc9_1_cyber_liability_insurance_test

import data.sigcomply.soc2.cc9_1_cyber_liability_insurance

test_overdue if {
	result := cc9_1_cyber_liability_insurance.violations with input as {
		"resource_type": "manual:cyber_liability_insurance",
		"resource_id": "cyber_liability_insurance/2026",
		"data": {
			"evidence_id": "cyber_liability_insurance",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc9_1_cyber_liability_insurance.violations with input as {
		"resource_type": "manual:cyber_liability_insurance",
		"resource_id": "cyber_liability_insurance/2026",
		"data": {
			"evidence_id": "cyber_liability_insurance",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "insurance.pdf", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc9_1_cyber_liability_insurance.violations with input as {
		"resource_type": "manual:cyber_liability_insurance",
		"resource_id": "cyber_liability_insurance/2026",
		"data": {
			"evidence_id": "cyber_liability_insurance",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "insurance.pdf", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc9_1_cyber_liability_insurance.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
