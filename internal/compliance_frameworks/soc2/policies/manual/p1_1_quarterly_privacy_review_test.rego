package sigcomply.soc2.p1_1_quarterly_privacy_review_test

import data.sigcomply.soc2.p1_1_quarterly_privacy_review

test_overdue if {
	result := p1_1_quarterly_privacy_review.violations with input as {
		"resource_type": "manual:quarterly_privacy_review",
		"resource_id": "quarterly_privacy_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_privacy_review",
			"type": "checklist",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_all_checked if {
	result := p1_1_quarterly_privacy_review.violations with input as {
		"resource_type": "manual:quarterly_privacy_review",
		"resource_id": "quarterly_privacy_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_privacy_review",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"items": [
				{"id": "notice_reviewed", "text": "Privacy notice reviewed", "required": true, "checked": true},
				{"id": "dsar_log_reviewed", "text": "DSAR log reviewed", "required": true, "checked": true},
				{"id": "consent_audited", "text": "Consent records audited", "required": true, "checked": true},
				{"id": "minimization_reviewed", "text": "Data minimization reviewed", "required": true, "checked": true},
			],
		},
	}
	count(result) == 0
}

test_required_unchecked if {
	result := p1_1_quarterly_privacy_review.violations with input as {
		"resource_type": "manual:quarterly_privacy_review",
		"resource_id": "quarterly_privacy_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_privacy_review",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"items": [
				{"id": "notice_reviewed", "text": "Privacy notice reviewed", "required": true, "checked": false},
				{"id": "dsar_log_reviewed", "text": "DSAR log reviewed", "required": true, "checked": true},
				{"id": "consent_audited", "text": "Consent records audited", "required": true, "checked": true},
				{"id": "minimization_reviewed", "text": "Data minimization reviewed", "required": true, "checked": true},
			],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := p1_1_quarterly_privacy_review.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
