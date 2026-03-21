package sigcomply.soc2.cc6_3_iam_policy_attached_to_groups_roles_test

import data.sigcomply.soc2.cc6_3_iam_policy_attached_to_groups_roles

test_policies_attached if {
	result := cc6_3_iam_policy_attached_to_groups_roles.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {"username": "alice", "attached_policy_count": 2},
	}
	count(result) == 1
}

test_no_policies_attached if {
	result := cc6_3_iam_policy_attached_to_groups_roles.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {"username": "alice", "attached_policy_count": 0},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_3_iam_policy_attached_to_groups_roles.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_3_iam_policy_attached_to_groups_roles.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
