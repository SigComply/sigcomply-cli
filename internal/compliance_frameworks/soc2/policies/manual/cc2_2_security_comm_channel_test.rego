package sigcomply.soc2.cc2_2_security_comm_channel_test

import data.sigcomply.soc2.cc2_2_security_comm_channel

test_overdue if {
	result := cc2_2_security_comm_channel.violations with input as {
		"resource_type": "manual:security_comm_channel",
		"resource_id": "security_comm_channel/2026-Q1",
		"data": {
			"evidence_id": "security_comm_channel",
			"type": "declaration",
			"status": "not_uploaded",
			"period": "2026-Q1",
			"temporal_status": "overdue",
		},
	}
	count(result) == 1
}

test_accepted if {
	result := cc2_2_security_comm_channel.violations with input as {
		"resource_type": "manual:security_comm_channel",
		"resource_id": "security_comm_channel/2026-Q1",
		"data": {
			"evidence_id": "security_comm_channel",
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
	result := cc2_2_security_comm_channel.violations with input as {
		"resource_type": "manual:security_comm_channel",
		"resource_id": "security_comm_channel/2026-Q1",
		"data": {
			"evidence_id": "security_comm_channel",
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
	result := cc2_2_security_comm_channel.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn",
		"data": {"status": "not_uploaded", "temporal_status": "overdue"},
	}
	count(result) == 0
}
