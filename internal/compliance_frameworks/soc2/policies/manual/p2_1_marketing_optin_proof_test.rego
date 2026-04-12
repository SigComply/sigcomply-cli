package sigcomply.soc2.p2_1_marketing_optin_proof_test

import data.sigcomply.soc2.p2_1_marketing_optin_proof

test_overdue if {
	result := p2_1_marketing_optin_proof.violations with input as {
		"resource_type": "manual:marketing_optin_proof",
		"resource_id": "marketing_optin_proof/2026-Q1",
		"data": {
			"evidence_id": "marketing_optin_proof",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := p2_1_marketing_optin_proof.violations with input as {
		"resource_type": "manual:marketing_optin_proof",
		"resource_id": "marketing_optin_proof/2026-Q1",
		"data": {
			"evidence_id": "marketing_optin_proof",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "optin.pdf", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := p2_1_marketing_optin_proof.violations with input as {
		"resource_type": "manual:marketing_optin_proof",
		"resource_id": "marketing_optin_proof/2026-Q1",
		"data": {
			"evidence_id": "marketing_optin_proof",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "optin.pdf", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := p2_1_marketing_optin_proof.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
