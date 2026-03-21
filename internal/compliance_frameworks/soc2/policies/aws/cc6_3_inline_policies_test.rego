package sigcomply.soc2.cc6_3_inline_policies_test

import data.sigcomply.soc2.cc6_3_inline_policies

# Test: user with inline policies should violate
test_has_inline_policies if {
	result := cc6_3_inline_policies.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"inline_policy_count": 2,
		},
	}
	count(result) == 1
}

# Test: user with no inline policies should pass
test_no_inline_policies if {
	result := cc6_3_inline_policies.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {
			"user_name": "bob",
			"inline_policy_count": 0,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_3_inline_policies.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"inline_policy_count": 2},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_3_inline_policies.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/test",
		"data": {},
	}
	count(result) == 0
}
