package sigcomply.soc2.cc1_4_background_check_test

import data.sigcomply.soc2.cc1_4_background_check

test_overdue_not_uploaded if {
	result := cc1_4_background_check.violations with input as {
		"resource_type": "manual:background_check",
		"resource_id": "background_check/2026",
		"data": {
			"evidence_id": "background_check",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_within_window_not_uploaded if {
	result := cc1_4_background_check.violations with input as {
		"resource_type": "manual:background_check",
		"resource_id": "background_check/2026",
		"data": {
			"evidence_id": "background_check",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

test_accepted_declaration if {
	result := cc1_4_background_check.violations with input as {
		"resource_type": "manual:background_check",
		"resource_id": "background_check/2026",
		"data": {
			"evidence_id": "background_check",
			"type": "declaration",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": true,
		},
	}
	count(result) == 0
}

test_unaccepted_declaration if {
	result := cc1_4_background_check.violations with input as {
		"resource_type": "manual:background_check",
		"resource_id": "background_check/2026",
		"data": {
			"evidence_id": "background_check",
			"type": "declaration",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": false,
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc1_4_background_check.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
