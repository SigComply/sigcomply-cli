package sigcomply.soc2.cc7_4_incident_response_test_test

import data.sigcomply.soc2.cc7_4_incident_response_test

# Test: overdue not uploaded
test_overdue if {
	result := cc7_4_incident_response_test.violations with input as {
		"resource_type": "manual:incident_response_test",
		"resource_id": "incident_response_test/2026",
		"data": {
			"evidence_id": "incident_response_test",
			"type": "checklist",
			"status": "not_uploaded",
			"period": "2026",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

# Test: all required items checked should pass
test_all_checked if {
	result := cc7_4_incident_response_test.violations with input as {
		"resource_type": "manual:incident_response_test",
		"resource_id": "incident_response_test/2026",
		"data": {
			"evidence_id": "incident_response_test",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"items": [
				{"id": "plan_tested", "text": "IR plan tested", "required": true, "checked": true},
				{"id": "roles_verified", "text": "Roles verified", "required": true, "checked": true},
				{"id": "communication_tested", "text": "Comms tested", "required": true, "checked": true},
				{"id": "lessons_documented", "text": "Lessons documented", "required": false, "checked": false},
			],
		},
	}
	count(result) == 0
}

# Test: required item unchecked should violate
test_required_unchecked if {
	result := cc7_4_incident_response_test.violations with input as {
		"resource_type": "manual:incident_response_test",
		"resource_id": "incident_response_test/2026",
		"data": {
			"evidence_id": "incident_response_test",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"items": [
				{"id": "plan_tested", "text": "IR plan tested", "required": true, "checked": false},
				{"id": "roles_verified", "text": "Roles verified", "required": true, "checked": true},
			],
		},
	}
	count(result) == 1
}

# Test: multiple required items unchecked
test_multiple_required_unchecked if {
	result := cc7_4_incident_response_test.violations with input as {
		"resource_type": "manual:incident_response_test",
		"resource_id": "incident_response_test/2026",
		"data": {
			"evidence_id": "incident_response_test",
			"status": "uploaded",
			"period": "2026",
			"temporal_status": "within_window",
			"hash_verified": true,
			"items": [
				{"id": "plan_tested", "text": "IR plan tested", "required": true, "checked": false},
				{"id": "roles_verified", "text": "Roles verified", "required": true, "checked": false},
			],
		},
	}
	count(result) == 2
}

# Test: wrong resource type
test_wrong_resource_type if {
	result := cc7_4_incident_response_test.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "some-arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
