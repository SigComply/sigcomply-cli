package sigcomply.soc2.cc6_8_hardening_standards_doc_test

import data.sigcomply.soc2.cc6_8_hardening_standards_doc

test_overdue if {
	result := cc6_8_hardening_standards_doc.violations with input as {
		"resource_type": "manual:hardening_standards_doc",
		"resource_id": "hardening_standards_doc/2026",
		"data": {
			"evidence_id": "hardening_standards_doc",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc6_8_hardening_standards_doc.violations with input as {
		"resource_type": "manual:hardening_standards_doc",
		"resource_id": "hardening_standards_doc/2026",
		"data": {
			"evidence_id": "hardening_standards_doc",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "hardening.pdf", "sha256": "abc", "size_bytes": 2048}],
		},
	}
	count(result) == 0
}

test_hash_failure if {
	result := cc6_8_hardening_standards_doc.violations with input as {
		"resource_type": "manual:hardening_standards_doc",
		"resource_id": "hardening_standards_doc/2026",
		"data": {
			"evidence_id": "hardening_standards_doc",
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
	result := cc6_8_hardening_standards_doc.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
