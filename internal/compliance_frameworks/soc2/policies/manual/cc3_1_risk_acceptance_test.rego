package sigcomply.soc2.cc3_1_risk_acceptance_test

import data.sigcomply.soc2.cc3_1_risk_acceptance

# Test: overdue not uploaded
test_overdue if {
	result := cc3_1_risk_acceptance.violations with input as {
		"resource_type": "manual:risk_acceptance_signoff",
		"resource_id": "risk_acceptance_signoff/2026-Q1",
		"data": {
			"evidence_id": "risk_acceptance_signoff",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

# Test: accepted should pass
test_accepted if {
	result := cc3_1_risk_acceptance.violations with input as {
		"resource_type": "manual:risk_acceptance_signoff",
		"resource_id": "risk_acceptance_signoff/2026-Q1",
		"data": {
			"evidence_id": "risk_acceptance_signoff",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": true,
			"declaration_text": "I confirm...",
		},
	}
	count(result) == 0
}

# Test: not accepted should violate
test_not_accepted if {
	result := cc3_1_risk_acceptance.violations with input as {
		"resource_type": "manual:risk_acceptance_signoff",
		"resource_id": "risk_acceptance_signoff/2026-Q1",
		"data": {
			"evidence_id": "risk_acceptance_signoff",
			"status": "uploaded",
			"period": "2026-Q1",
			"temporal_status": "within_window",
			"hash_verified": true,
			"accepted": false,
		},
	}
	count(result) == 1
}

# Test: within window not uploaded should pass
test_within_window if {
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

# Test: wrong resource type
test_wrong_resource_type if {
	result := cc3_1_risk_acceptance.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "some-arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
