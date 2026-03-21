package sigcomply.soc2.cc6_1_iam_support_role_test

import data.sigcomply.soc2.cc6_1_iam_support_role

# Test: no support role should violate
test_no_support_role if {
	result := cc6_1_iam_support_role.violations with input as {
		"resource_type": "aws:iam:support-role-status",
		"resource_id": "arn:aws:iam::123456789012:support-role-status",
		"data": {
			"has_support_role": false,
		},
	}
	count(result) == 1
}

# Test: support role exists should pass
test_has_support_role if {
	result := cc6_1_iam_support_role.violations with input as {
		"resource_type": "aws:iam:support-role-status",
		"resource_id": "arn:aws:iam::123456789012:support-role-status",
		"data": {
			"has_support_role": true,
			"role_arn": "arn:aws:iam::123456789012:role/AWSSupportRole",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_iam_support_role.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123456789012:user/alice",
		"data": {"has_support_role": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_1_iam_support_role.violations with input as {
		"resource_type": "aws:iam:support-role-status",
		"resource_id": "arn:aws:iam::123456789012:support-role-status",
		"data": {},
	}
	count(result) == 0
}
