package sigcomply.soc2.cc6_3_unused_test

import data.sigcomply.soc2.cc6_3_unused

# Test: active SA with no keys should violate (potentially unused)
test_no_keys_active if {
	result := cc6_3_unused.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "unused@proj.iam.gserviceaccount.com",
		"data": {
			"email": "unused@proj.iam.gserviceaccount.com",
			"disabled": false,
			"key_count": 0,
		},
	}
	count(result) == 1
}

# Test: SA with keys should pass
test_has_keys if {
	result := cc6_3_unused.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "active@proj.iam.gserviceaccount.com",
		"data": {
			"email": "active@proj.iam.gserviceaccount.com",
			"disabled": false,
			"key_count": 1,
		},
	}
	count(result) == 0
}

# Test: disabled SA with no keys should pass
test_disabled if {
	result := cc6_3_unused.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "disabled@proj.iam.gserviceaccount.com",
		"data": {
			"email": "disabled@proj.iam.gserviceaccount.com",
			"disabled": true,
			"key_count": 0,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_3_unused.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {"disabled": false, "key_count": 0},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_3_unused.violations with input as {
		"resource_type": "gcp:iam:service-account",
		"resource_id": "empty@proj.iam.gserviceaccount.com",
		"data": {},
	}
	count(result) == 0
}
