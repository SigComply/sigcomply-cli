package sigcomply.soc2.cc3_3_fraud_risk_assessment_test

import data.sigcomply.soc2.cc3_3_fraud_risk_assessment

test_overdue if {
	result := cc3_3_fraud_risk_assessment.violations with input as {
		"resource_type": "manual:fraud_risk_assessment",
		"resource_id": "fraud_risk_assessment/2026",
		"data": {
			"evidence_id": "fraud_risk_assessment",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc3_3_fraud_risk_assessment.violations with input as {
		"resource_type": "manual:fraud_risk_assessment",
		"resource_id": "fraud_risk_assessment/2026",
		"data": {
			"evidence_id": "fraud_risk_assessment",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "fraud.pdf", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_hash_failure if {
	result := cc3_3_fraud_risk_assessment.violations with input as {
		"resource_type": "manual:fraud_risk_assessment",
		"resource_id": "fraud_risk_assessment/2026",
		"data": {
			"evidence_id": "fraud_risk_assessment",
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
	result := cc3_3_fraud_risk_assessment.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
