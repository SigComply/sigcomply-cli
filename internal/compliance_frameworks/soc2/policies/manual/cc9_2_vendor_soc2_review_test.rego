package sigcomply.soc2.cc9_2_vendor_soc2_review_test

import data.sigcomply.soc2.cc9_2_vendor_soc2_review

test_overdue if {
	result := cc9_2_vendor_soc2_review.violations with input as {
		"resource_type": "manual:vendor_soc2_review",
		"resource_id": "vendor_soc2_review/2026",
		"data": {
			"evidence_id": "vendor_soc2_review",
			"type": "checklist",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_all_checked if {
	result := cc9_2_vendor_soc2_review.violations with input as {
		"resource_type": "manual:vendor_soc2_review",
		"resource_id": "vendor_soc2_review/2026",
		"data": {
			"evidence_id": "vendor_soc2_review",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"items": [
				{"id": "all_vendors_reviewed", "text": "all reviewed", "required": true, "checked": true},
				{"id": "exceptions_documented", "text": "exceptions", "required": true, "checked": true},
				{"id": "cuecs_addressed", "text": "cuecs", "required": true, "checked": true},
			],
		},
	}
	count(result) == 0
}

test_required_unchecked if {
	result := cc9_2_vendor_soc2_review.violations with input as {
		"resource_type": "manual:vendor_soc2_review",
		"resource_id": "vendor_soc2_review/2026",
		"data": {
			"evidence_id": "vendor_soc2_review",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"items": [
				{"id": "all_vendors_reviewed", "text": "all reviewed", "required": true, "checked": false},
				{"id": "exceptions_documented", "text": "exceptions", "required": true, "checked": true},
				{"id": "cuecs_addressed", "text": "cuecs", "required": true, "checked": true},
			],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc9_2_vendor_soc2_review.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
