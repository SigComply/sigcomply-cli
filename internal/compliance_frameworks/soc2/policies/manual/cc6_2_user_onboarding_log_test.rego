package sigcomply.soc2.cc6_2_user_onboarding_log_test

import data.sigcomply.soc2.cc6_2_user_onboarding_log

test_overdue if {
	result := cc6_2_user_onboarding_log.violations with input as {
		"resource_type": "manual:user_onboarding_log",
		"resource_id": "user_onboarding_log/2026-Q1",
		"data": {
			"evidence_id": "user_onboarding_log",
			"type": "document_upload",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_uploaded_verified if {
	result := cc6_2_user_onboarding_log.violations with input as {
		"resource_type": "manual:user_onboarding_log",
		"resource_id": "user_onboarding_log/2026-Q1",
		"data": {
			"evidence_id": "user_onboarding_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "onboarding.csv", "sha256": "abc", "size_bytes": 1024}],
		},
	}
	count(result) == 0
}

test_missing_attachment if {
	result := cc6_2_user_onboarding_log.violations with input as {
		"resource_type": "manual:user_onboarding_log",
		"resource_id": "user_onboarding_log/2026-Q1",
		"data": {
			"evidence_id": "user_onboarding_log",
			"type": "document_upload",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"files": [{"name": "onboarding.csv", "error": "not_found"}],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_2_user_onboarding_log.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
