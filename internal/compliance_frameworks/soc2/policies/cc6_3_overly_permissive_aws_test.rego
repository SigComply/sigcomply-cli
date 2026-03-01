package sigcomply.soc2.cc6_3_permissive_aws_test

import data.sigcomply.soc2.cc6_3_permissive_aws

# Test: user with AdministratorAccess should violate
test_admin_policy if {
	result := cc6_3_permissive_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/admin",
		"data": {
			"user_name": "admin",
			"has_admin_policy": true,
			"attached_policies": [
				{"policy_name": "AdministratorAccess", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
			],
		},
	}
	count(result) == 1
}

# Test: user without AdministratorAccess should pass
test_no_admin_policy if {
	result := cc6_3_permissive_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/reader",
		"data": {
			"user_name": "reader",
			"has_admin_policy": false,
			"attached_policies": [
				{"policy_name": "ReadOnlyAccess", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
			],
		},
	}
	count(result) == 0
}

# Test: user with no attached policies should pass
test_no_policies if {
	result := cc6_3_permissive_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/minimal",
		"data": {
			"user_name": "minimal",
			"has_admin_policy": false,
			"attached_policies": [],
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_3_permissive_aws.violations with input as {
		"resource_type": "gcp:iam:policy",
		"resource_id": "project",
		"data": {"has_admin_policy": true},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_3_permissive_aws.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/empty",
		"data": {},
	}
	count(result) == 0
}
