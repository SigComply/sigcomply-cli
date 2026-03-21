package sigcomply.soc2.cc6_1_iam_user_groups_test

import data.sigcomply.soc2.cc6_1_iam_user_groups

# Test: no groups but has inline policies should violate
test_no_groups_with_inline_policies if {
	result := cc6_1_iam_user_groups.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"group_count": 0,
			"inline_policy_count": 2,
			"attached_policies": [],
		},
	}
	count(result) == 1
}

# Test: no groups but has attached policies should violate
test_no_groups_with_attached_policies if {
	result := cc6_1_iam_user_groups.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {
			"user_name": "bob",
			"group_count": 0,
			"inline_policy_count": 0,
			"attached_policies": [{"policy_name": "ReadOnly", "policy_arn": "arn:aws:iam::aws:policy/ReadOnly"}],
		},
	}
	count(result) == 1
}

# Test: has groups should pass
test_has_groups if {
	result := cc6_1_iam_user_groups.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/charlie",
		"data": {
			"user_name": "charlie",
			"group_count": 1,
			"inline_policy_count": 2,
			"attached_policies": [{"policy_name": "Admin", "policy_arn": "arn:aws:iam::aws:policy/Admin"}],
		},
	}
	count(result) == 0
}

# Test: no groups and no policies should pass
test_no_groups_no_policies if {
	result := cc6_1_iam_user_groups.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/dave",
		"data": {
			"user_name": "dave",
			"group_count": 0,
			"inline_policy_count": 0,
			"attached_policies": [],
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not trigger
test_wrong_resource_type if {
	result := cc6_1_iam_user_groups.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"group_count": 0,
			"inline_policy_count": 2,
			"attached_policies": [],
		},
	}
	count(result) == 0
}
