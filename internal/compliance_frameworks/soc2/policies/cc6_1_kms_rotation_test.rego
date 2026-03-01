package sigcomply.soc2.cc6_1_kms_rotation_test

import data.sigcomply.soc2.cc6_1_kms_rotation

# Test: enabled key without rotation should violate
test_no_rotation if {
	result := cc6_1_kms_rotation.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {
			"key_id": "abc",
			"enabled": true,
			"rotation_enabled": false,
			"key_state": "Enabled",
		},
	}
	count(result) == 1
}

# Test: enabled key with rotation should pass
test_with_rotation if {
	result := cc6_1_kms_rotation.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {
			"key_id": "abc",
			"enabled": true,
			"rotation_enabled": true,
		},
	}
	count(result) == 0
}

# Test: disabled key without rotation should not violate
test_disabled_key if {
	result := cc6_1_kms_rotation.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {
			"key_id": "abc",
			"enabled": false,
			"rotation_enabled": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_kms_rotation.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": true, "rotation_enabled": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_1_kms_rotation.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {},
	}
	count(result) == 0
}
