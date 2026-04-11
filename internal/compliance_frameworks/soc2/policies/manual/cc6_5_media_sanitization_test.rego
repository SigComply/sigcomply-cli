package sigcomply.soc2.cc6_5_media_sanitization_test

import data.sigcomply.soc2.cc6_5_media_sanitization

test_overdue if {
	result := cc6_5_media_sanitization.violations with input as {
		"resource_type": "manual:media_sanitization",
		"resource_id": "media_sanitization/2026-Q1",
		"data": {
			"evidence_id": "media_sanitization",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_accepted if {
	result := cc6_5_media_sanitization.violations with input as {
		"resource_type": "manual:media_sanitization",
		"resource_id": "media_sanitization/2026-Q1",
		"data": {
			"evidence_id": "media_sanitization",
			"type": "declaration",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": true,
		},
	}
	count(result) == 0
}

test_unaccepted if {
	result := cc6_5_media_sanitization.violations with input as {
		"resource_type": "manual:media_sanitization",
		"resource_id": "media_sanitization/2026-Q1",
		"data": {
			"evidence_id": "media_sanitization",
			"type": "declaration",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": false,
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_5_media_sanitization.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
