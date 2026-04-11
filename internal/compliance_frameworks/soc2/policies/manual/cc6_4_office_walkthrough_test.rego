package sigcomply.soc2.cc6_4_office_walkthrough_test

import data.sigcomply.soc2.cc6_4_office_walkthrough

test_overdue if {
	result := cc6_4_office_walkthrough.violations with input as {
		"resource_type": "manual:office_walkthrough",
		"resource_id": "office_walkthrough/2026-Q1",
		"data": {
			"evidence_id": "office_walkthrough",
			"type": "checklist",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_all_checked if {
	result := cc6_4_office_walkthrough.violations with input as {
		"resource_type": "manual:office_walkthrough",
		"resource_id": "office_walkthrough/2026-Q1",
		"data": {
			"evidence_id": "office_walkthrough",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"items": [
				{"id": "it_closet_locked", "text": "locked", "required": true, "checked": true},
				{"id": "clean_desk", "text": "desk", "required": true, "checked": true},
				{"id": "cctv_functioning", "text": "cctv", "required": true, "checked": true},
				{"id": "no_violations", "text": "none", "required": true, "checked": true},
			],
		},
	}
	count(result) == 0
}

test_required_unchecked if {
	result := cc6_4_office_walkthrough.violations with input as {
		"resource_type": "manual:office_walkthrough",
		"resource_id": "office_walkthrough/2026-Q1",
		"data": {
			"evidence_id": "office_walkthrough",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"items": [
				{"id": "it_closet_locked", "text": "locked", "required": true, "checked": false},
				{"id": "clean_desk", "text": "desk", "required": true, "checked": true},
				{"id": "cctv_functioning", "text": "cctv", "required": true, "checked": true},
				{"id": "no_violations", "text": "none", "required": true, "checked": true},
			],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_4_office_walkthrough.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
