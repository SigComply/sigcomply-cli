package sigcomply.soc2.cc6_3_unused_aws_test

import data.sigcomply.soc2.cc6_3_unused_aws

# Test: console user inactive for >90 days should violate
test_password_inactive if {
	result := cc6_3_unused_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"has_login_profile": true,
			"password_inactive_days": 120,
			"access_keys": [],
		},
	}
	count(result) == 1
}

# Test: console user active within 90 days should pass
test_password_active if {
	result := cc6_3_unused_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"has_login_profile": true,
			"password_inactive_days": 30,
			"access_keys": [],
		},
	}
	count(result) == 0
}

# Test: active key unused for >90 days should violate
test_key_unused if {
	result := cc6_3_unused_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {
			"user_name": "bob",
			"has_login_profile": false,
			"password_inactive_days": -1,
			"access_keys": [
				{
					"access_key_id": "AKIA111",
					"status": "Active",
					"last_used_days": 100,
					"age_days": 200,
				},
			],
		},
	}
	count(result) == 1
}

# Test: active key never used and >90 days old should violate
test_key_never_used_old if {
	result := cc6_3_unused_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/charlie",
		"data": {
			"user_name": "charlie",
			"has_login_profile": false,
			"password_inactive_days": -1,
			"access_keys": [
				{
					"access_key_id": "AKIA222",
					"status": "Active",
					"last_used_days": -1,
					"age_days": 100,
				},
			],
		},
	}
	count(result) == 1
}

# Test: active key never used but <90 days old should pass
test_key_never_used_new if {
	result := cc6_3_unused_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/new",
		"data": {
			"user_name": "new",
			"has_login_profile": false,
			"password_inactive_days": -1,
			"access_keys": [
				{
					"access_key_id": "AKIA333",
					"status": "Active",
					"last_used_days": -1,
					"age_days": 30,
				},
			],
		},
	}
	count(result) == 0
}

# Test: inactive key unused should pass (not active)
test_inactive_key_unused if {
	result := cc6_3_unused_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/old",
		"data": {
			"user_name": "old",
			"has_login_profile": false,
			"password_inactive_days": -1,
			"access_keys": [
				{
					"access_key_id": "AKIA444",
					"status": "Inactive",
					"last_used_days": 200,
					"age_days": 300,
				},
			],
		},
	}
	count(result) == 0
}

# Test: programmatic user without login profile should not trigger password violation
test_no_login_profile if {
	result := cc6_3_unused_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bot",
		"data": {
			"user_name": "bot",
			"has_login_profile": false,
			"password_inactive_days": -1,
			"access_keys": [],
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_3_unused_aws.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"has_login_profile": true,
			"password_inactive_days": 120,
		},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_3_unused_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/empty",
		"data": {},
	}
	count(result) == 0
}
