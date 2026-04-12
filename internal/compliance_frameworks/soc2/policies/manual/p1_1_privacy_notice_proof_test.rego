package sigcomply.soc2.p1_1_privacy_notice_proof_test

import data.sigcomply.soc2.p1_1_privacy_notice_proof

test_overdue if {
	result := p1_1_privacy_notice_proof.violations with input as {
		"resource_type": "manual:privacy_notice_proof",
		"resource_id": "privacy_notice_proof/2026",
		"data": {
			"evidence_id": "privacy_notice_proof",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := p1_1_privacy_notice_proof.violations with input as {
		"resource_type": "manual:privacy_notice_proof",
		"resource_id": "privacy_notice_proof/2026",
		"data": {
			"evidence_id": "privacy_notice_proof",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "notice.pdf", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_hash_failure if {
	result := p1_1_privacy_notice_proof.violations with input as {
		"resource_type": "manual:privacy_notice_proof",
		"resource_id": "privacy_notice_proof/2026",
		"data": {
			"evidence_id": "privacy_notice_proof",
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
	result := p1_1_privacy_notice_proof.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
