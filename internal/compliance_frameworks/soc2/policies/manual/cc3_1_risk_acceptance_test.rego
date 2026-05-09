package sigcomply.soc2.cc3_1_risk_acceptance_test

import data.sigcomply.soc2.cc3_1_risk_acceptance

# Overdue + not_uploaded → one violation
test_overdue_not_uploaded if {
	result := cc3_1_risk_acceptance.violations with input as {
		"resource_type": "manual:risk_acceptance_signoff",
		"resource_id": "risk_acceptance_signoff/2026-Q1",
		"data": {
			"evidence_id": "risk_acceptance_signoff",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

# Uploaded within window → no violation
test_uploaded_within_window if {
	result := cc3_1_risk_acceptance.violations with input as {
		"resource_type": "manual:risk_acceptance_signoff",
		"resource_id": "risk_acceptance_signoff/2026-Q1",
		"data": {
			"evidence_id": "risk_acceptance_signoff",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"file_hash": "abc123",
			"file_path": "soc2/risk_acceptance_signoff/2026-Q1/evidence.pdf",
		},
	}
	count(result) == 0
}

# Not-uploaded but within window → no violation (still in grace)
test_within_window_not_uploaded if {
	result := cc3_1_risk_acceptance.violations with input as {
		"resource_type": "manual:risk_acceptance_signoff",
		"resource_id": "risk_acceptance_signoff/2026-Q1",
		"data": {
			"evidence_id": "risk_acceptance_signoff",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
		},
	}
	count(result) == 0
}

# Wrong resource_type → no violation
test_wrong_resource_type if {
	result := cc3_1_risk_acceptance.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/x",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
