package sigcomply.soc2.a1_2_business_continuity_plan_test

import data.sigcomply.soc2.a1_2_business_continuity_plan

test_overdue if {
	result := a1_2_business_continuity_plan.violations with input as {
		"resource_type": "manual:business_continuity_plan",
		"resource_id": "business_continuity_plan/2026",
		"data": {
			"evidence_id": "business_continuity_plan",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := a1_2_business_continuity_plan.violations with input as {
		"resource_type": "manual:business_continuity_plan",
		"resource_id": "business_continuity_plan/2026",
		"data": {
			"evidence_id": "business_continuity_plan",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "bcp.pdf", "sha256": "abc", "size_bytes": 2048}],
		},
	}
	count(result) == 0
}

test_hash_failure if {
	result := a1_2_business_continuity_plan.violations with input as {
		"resource_type": "manual:business_continuity_plan",
		"resource_id": "business_continuity_plan/2026",
		"data": {
			"evidence_id": "business_continuity_plan",
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
	result := a1_2_business_continuity_plan.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
