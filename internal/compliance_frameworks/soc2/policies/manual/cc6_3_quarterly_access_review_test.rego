package sigcomply.soc2.cc6_3_quarterly_access_review_test

import data.sigcomply.soc2.cc6_3_quarterly_access_review

# Overdue + not_uploaded → one violation
test_overdue_not_uploaded if {
	result := cc6_3_quarterly_access_review.violations with input as {
		"resource_type": "manual:quarterly_access_review",
		"resource_id": "quarterly_access_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_access_review",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

# Uploaded within window → no violation
test_uploaded_within_window if {
	result := cc6_3_quarterly_access_review.violations with input as {
		"resource_type": "manual:quarterly_access_review",
		"resource_id": "quarterly_access_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_access_review",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"file_hash": "abc123",
			"file_path": "soc2/quarterly_access_review/2026-Q1/evidence.pdf",
		},
	}
	count(result) == 0
}

# Not-uploaded but within window → no violation (still in grace)
test_within_window_not_uploaded if {
	result := cc6_3_quarterly_access_review.violations with input as {
		"resource_type": "manual:quarterly_access_review",
		"resource_id": "quarterly_access_review/2026-Q1",
		"data": {
			"evidence_id": "quarterly_access_review",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

# Wrong resource_type → no violation
test_wrong_resource_type if {
	result := cc6_3_quarterly_access_review.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/x",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
