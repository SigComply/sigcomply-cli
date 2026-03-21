package sigcomply.soc2.cc6_1_access_key_rotation_test

import data.sigcomply.soc2.cc6_1_access_key_rotation

# Test: active key older than 90 days should violate
test_old_active_key if {
	result := cc6_1_access_key_rotation.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"active_key_count": 1,
			"oldest_key_age_days": 120,
		},
	}
	count(result) == 1
}

# Test: active key within 90 days should pass
test_fresh_active_key if {
	result := cc6_1_access_key_rotation.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"active_key_count": 1,
			"oldest_key_age_days": 45,
		},
	}
	count(result) == 0
}

# Test: no active keys should pass (even if oldest_key_age_days > 90)
test_no_active_keys if {
	result := cc6_1_access_key_rotation.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"active_key_count": 0,
			"oldest_key_age_days": 0,
		},
	}
	count(result) == 0
}

# Test: exactly 90 days should pass (> 90 required)
test_exactly_90_days if {
	result := cc6_1_access_key_rotation.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"active_key_count": 1,
			"oldest_key_age_days": 90,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_access_key_rotation.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"active_key_count": 1,
			"oldest_key_age_days": 120,
		},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_1_access_key_rotation.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/empty",
		"data": {},
	}
	count(result) == 0
}
