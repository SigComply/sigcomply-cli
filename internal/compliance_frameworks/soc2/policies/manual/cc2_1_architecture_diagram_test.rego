package sigcomply.soc2.cc2_1_architecture_diagram_test

import data.sigcomply.soc2.cc2_1_architecture_diagram

test_overdue if {
	result := cc2_1_architecture_diagram.violations with input as {
		"resource_type": "manual:architecture_diagram",
		"resource_id": "architecture_diagram/2026",
		"data": {
			"evidence_id": "architecture_diagram",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc2_1_architecture_diagram.violations with input as {
		"resource_type": "manual:architecture_diagram",
		"resource_id": "architecture_diagram/2026",
		"data": {
			"evidence_id": "architecture_diagram",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "arch.pdf", "sha256": "abc", "size_bytes": 4096}],
		},
	}
	count(result) == 0
}

test_hash_failure if {
	result := cc2_1_architecture_diagram.violations with input as {
		"resource_type": "manual:architecture_diagram",
		"resource_id": "architecture_diagram/2026",
		"data": {
			"evidence_id": "architecture_diagram",
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
	result := cc2_1_architecture_diagram.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
