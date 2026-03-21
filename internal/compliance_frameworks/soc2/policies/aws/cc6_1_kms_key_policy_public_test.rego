package sigcomply.soc2.cc6_1_kms_key_policy_public_test

import data.sigcomply.soc2.cc6_1_kms_key_policy_public

# Test: public key policy should violate
test_public_key_policy if {
	result := cc6_1_kms_key_policy_public.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {
			"key_id": "abc",
			"key_arn": "arn:aws:kms:us-east-1:123:key/abc",
			"enabled": true,
			"key_policy_public": true,
		},
	}
	count(result) == 1
}

# Test: non-public key policy should pass
test_private_key_policy if {
	result := cc6_1_kms_key_policy_public.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {
			"key_id": "abc",
			"key_arn": "arn:aws:kms:us-east-1:123:key/abc",
			"enabled": true,
			"key_policy_public": false,
		},
	}
	count(result) == 0
}

# Test: disabled key with public policy should not violate
test_disabled_key if {
	result := cc6_1_kms_key_policy_public.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {
			"key_id": "abc",
			"enabled": false,
			"key_policy_public": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_kms_key_policy_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": true, "key_policy_public": true},
	}
	count(result) == 0
}
