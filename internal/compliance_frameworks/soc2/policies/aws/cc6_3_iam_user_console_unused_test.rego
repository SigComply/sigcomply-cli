package sigcomply.soc2.cc6_3_iam_user_console_unused_test

import data.sigcomply.soc2.cc6_3_iam_user_console_unused

test_unused_console if {
	result := cc6_3_iam_user_console_unused.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {"username": "alice", "has_console_access": true, "console_last_used_days": 120},
	}
	count(result) == 1
}

test_recently_used if {
	result := cc6_3_iam_user_console_unused.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {"username": "alice", "has_console_access": true, "console_last_used_days": 30},
	}
	count(result) == 0
}

test_no_console_access if {
	result := cc6_3_iam_user_console_unused.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {"username": "alice", "has_console_access": false, "console_last_used_days": 120},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_3_iam_user_console_unused.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_3_iam_user_console_unused.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
