package sigcomply.soc2.cc6_1_key_rotation_test

import data.sigcomply.soc2.cc6_1_key_rotation

# Test: service account with old keys should violate
test_old_keys if {
	result := cc6_1_key_rotation.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "sa@project.iam.gserviceaccount.com",
		"data": {
			"email": "sa@project.iam.gserviceaccount.com",
			"key_count": 2,
			"oldest_key_age_days": 120,
		},
	}
	count(result) == 1
}

# Test: service account with fresh keys should pass
test_fresh_keys if {
	result := cc6_1_key_rotation.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "sa@project.iam.gserviceaccount.com",
		"data": {
			"email": "sa@project.iam.gserviceaccount.com",
			"key_count": 1,
			"oldest_key_age_days": 30,
		},
	}
	count(result) == 0
}

# Test: service account with no keys should pass
test_no_keys if {
	result := cc6_1_key_rotation.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "sa@project.iam.gserviceaccount.com",
		"data": {
			"email": "sa@project.iam.gserviceaccount.com",
			"key_count": 0,
			"oldest_key_age_days": 0,
		},
	}
	count(result) == 0
}

# Test: keys exactly at 90 days should pass
test_keys_at_boundary if {
	result := cc6_1_key_rotation.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "sa@project.iam.gserviceaccount.com",
		"data": {
			"email": "sa@project.iam.gserviceaccount.com",
			"key_count": 1,
			"oldest_key_age_days": 90,
		},
	}
	count(result) == 0
}

# Negative: keys at 91 days should violate (boundary + 1)
test_keys_just_over_boundary if {
	result := cc6_1_key_rotation.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "sa@project.iam.gserviceaccount.com",
		"data": {
			"email": "sa@project.iam.gserviceaccount.com",
			"key_count": 1,
			"oldest_key_age_days": 91,
		},
	}
	count(result) == 1
}

# Negative: wrong resource type should not trigger
test_wrong_resource_type if {
	result := cc6_1_key_rotation.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {
			"key_count": 2,
			"oldest_key_age_days": 120,
		},
	}
	count(result) == 0
}

# Negative: empty data should not trigger
test_empty_data if {
	result := cc6_1_key_rotation.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "sa@project.iam.gserviceaccount.com",
		"data": {},
	}
	count(result) == 0
}
