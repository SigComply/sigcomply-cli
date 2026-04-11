package sigcomply.soc2.cc3_2_annual_risk_assessment_test

import data.sigcomply.soc2.cc3_2_annual_risk_assessment

test_overdue if {
	result := cc3_2_annual_risk_assessment.violations with input as {
		"resource_type": "manual:annual_risk_assessment",
		"resource_id": "annual_risk_assessment/2026",
		"data": {
			"evidence_id": "annual_risk_assessment",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc3_2_annual_risk_assessment.violations with input as {
		"resource_type": "manual:annual_risk_assessment",
		"resource_id": "annual_risk_assessment/2026",
		"data": {
			"evidence_id": "annual_risk_assessment",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "risk.pdf", "sha256": "abc", "size_bytes": 4096}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc3_2_annual_risk_assessment.violations with input as {
		"resource_type": "manual:annual_risk_assessment",
		"resource_id": "annual_risk_assessment/2026",
		"data": {
			"evidence_id": "annual_risk_assessment",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "risk.pdf", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc3_2_annual_risk_assessment.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
