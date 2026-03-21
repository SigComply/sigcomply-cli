package sigcomply.soc2.cc6_1_test

import data.sigcomply.soc2.cc6_1

# Test: console user without MFA should violate
test_console_user_no_mfa if {
	result := cc6_1.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {
			"user_name": "bob",
			"user_id": "AIDA123",
			"has_login_profile": true,
			"mfa_enabled": false,
		},
	}
	count(result) == 1
}

# Test: console user with MFA should pass
test_console_user_with_mfa if {
	result := cc6_1.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"user_id": "AIDA456",
			"has_login_profile": true,
			"mfa_enabled": true,
		},
	}
	count(result) == 0
}

# Test: programmatic-only user without MFA should pass (exempt)
test_programmatic_user if {
	result := cc6_1.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/ci-bot",
		"data": {
			"user_name": "ci-bot",
			"user_id": "AIDA789",
			"has_login_profile": false,
			"mfa_enabled": false,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not trigger
test_wrong_resource_type if {
	result := cc6_1.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"has_login_profile": true,
			"mfa_enabled": false,
		},
	}
	count(result) == 0
}

# Test: empty data should not trigger
test_empty_data if {
	result := cc6_1.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/empty",
		"data": {},
	}
	count(result) == 0
}
