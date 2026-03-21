package sigcomply.soc2.c1_2_ecr_lifecycle_policy_test

import data.sigcomply.soc2.c1_2_ecr_lifecycle_policy

# Test: no lifecycle policy should violate
test_no_lifecycle_policy if {
	result := c1_2_ecr_lifecycle_policy.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/my-app",
		"data": {
			"name": "my-app",
			"has_lifecycle_policy": false,
		},
	}
	count(result) == 1
}

# Test: lifecycle policy exists should pass
test_has_lifecycle_policy if {
	result := c1_2_ecr_lifecycle_policy.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/my-app",
		"data": {
			"name": "my-app",
			"has_lifecycle_policy": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := c1_2_ecr_lifecycle_policy.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_lifecycle_policy": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := c1_2_ecr_lifecycle_policy.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/empty",
		"data": {},
	}
	count(result) == 0
}
