package sigcomply.soc2.cc8_1_emergency_change_procedure_test

import data.sigcomply.soc2.cc8_1_emergency_change_procedure

test_overdue if {
	result := cc8_1_emergency_change_procedure.violations with input as {
		"resource_type": "manual:emergency_change_procedure",
		"resource_id": "emergency_change_procedure/2026-Q1",
		"data": {
			"evidence_id": "emergency_change_procedure",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_accepted if {
	result := cc8_1_emergency_change_procedure.violations with input as {
		"resource_type": "manual:emergency_change_procedure",
		"resource_id": "emergency_change_procedure/2026-Q1",
		"data": {
			"evidence_id": "emergency_change_procedure",
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
	result := cc8_1_emergency_change_procedure.violations with input as {
		"resource_type": "manual:emergency_change_procedure",
		"resource_id": "emergency_change_procedure/2026-Q1",
		"data": {
			"evidence_id": "emergency_change_procedure",
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
	result := cc8_1_emergency_change_procedure.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
