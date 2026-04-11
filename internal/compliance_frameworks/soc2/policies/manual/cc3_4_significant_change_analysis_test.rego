package sigcomply.soc2.cc3_4_significant_change_analysis_test

import data.sigcomply.soc2.cc3_4_significant_change_analysis

test_overdue if {
	result := cc3_4_significant_change_analysis.violations with input as {
		"resource_type": "manual:significant_change_analysis",
		"resource_id": "significant_change_analysis/2026-Q1",
		"data": {
			"evidence_id": "significant_change_analysis",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_accepted if {
	result := cc3_4_significant_change_analysis.violations with input as {
		"resource_type": "manual:significant_change_analysis",
		"resource_id": "significant_change_analysis/2026-Q1",
		"data": {
			"evidence_id": "significant_change_analysis",
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
	result := cc3_4_significant_change_analysis.violations with input as {
		"resource_type": "manual:significant_change_analysis",
		"resource_id": "significant_change_analysis/2026-Q1",
		"data": {
			"evidence_id": "significant_change_analysis",
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
	result := cc3_4_significant_change_analysis.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
