package sigcomply.soc2.cc6_1_kms_wildcard_decrypt_test

import data.sigcomply.soc2.cc6_1_kms_wildcard_decrypt

# Test: wildcard KMS decrypt should violate
test_wildcard_decrypt if {
	result := cc6_1_kms_wildcard_decrypt.violations with input as {
		"resource_type": "aws:iam:policy",
		"resource_id": "arn:aws:iam::123:policy/wide-decrypt",
		"data": {
			"policy_name": "wide-decrypt",
			"policy_arn": "arn:aws:iam::123:policy/wide-decrypt",
			"has_wildcard_kms_decrypt": true,
		},
	}
	count(result) == 1
}

# Test: scoped KMS decrypt should pass
test_scoped_decrypt if {
	result := cc6_1_kms_wildcard_decrypt.violations with input as {
		"resource_type": "aws:iam:policy",
		"resource_id": "arn:aws:iam::123:policy/scoped-decrypt",
		"data": {
			"policy_name": "scoped-decrypt",
			"policy_arn": "arn:aws:iam::123:policy/scoped-decrypt",
			"has_wildcard_kms_decrypt": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_kms_wildcard_decrypt.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_wildcard_kms_decrypt": true},
	}
	count(result) == 0
}
