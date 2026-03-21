package sigcomply.soc2.cc6_1_multiple_active_keys_test

import data.sigcomply.soc2.cc6_1_multiple_active_keys

# Test: user with 2 active keys should violate
test_two_active_keys if {
	result := cc6_1_multiple_active_keys.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"active_key_count": 2,
		},
	}
	count(result) == 1
}

# Test: user with 1 active key should pass
test_one_active_key if {
	result := cc6_1_multiple_active_keys.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {
			"user_name": "bob",
			"active_key_count": 1,
		},
	}
	count(result) == 0
}

# Test: user with 0 active keys should pass
test_zero_active_keys if {
	result := cc6_1_multiple_active_keys.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/ci-bot",
		"data": {
			"user_name": "ci-bot",
			"active_key_count": 0,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not trigger
test_wrong_resource_type if {
	result := cc6_1_multiple_active_keys.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"active_key_count": 2,
		},
	}
	count(result) == 0
}

# Test: empty data should not trigger
test_empty_data if {
	result := cc6_1_multiple_active_keys.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/empty",
		"data": {},
	}
	count(result) == 0
}
