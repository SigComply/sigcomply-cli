package sigcomply.soc2.cc7_4_incident_post_mortem_test

import data.sigcomply.soc2.cc7_4_incident_post_mortem

test_overdue if {
	result := cc7_4_incident_post_mortem.violations with input as {
		"resource_type": "manual:incident_post_mortem",
		"resource_id": "incident_post_mortem/2026-Q1",
		"data": {
			"evidence_id": "incident_post_mortem",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_accepted if {
	result := cc7_4_incident_post_mortem.violations with input as {
		"resource_type": "manual:incident_post_mortem",
		"resource_id": "incident_post_mortem/2026-Q1",
		"data": {
			"evidence_id": "incident_post_mortem",
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
	result := cc7_4_incident_post_mortem.violations with input as {
		"resource_type": "manual:incident_post_mortem",
		"resource_id": "incident_post_mortem/2026-Q1",
		"data": {
			"evidence_id": "incident_post_mortem",
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
	result := cc7_4_incident_post_mortem.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
