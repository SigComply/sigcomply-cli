package sigcomply.soc2.cc5_1_iam_permission_boundary_test

import data.sigcomply.soc2.cc5_1_iam_permission_boundary

test_no_boundary if {
	result := cc5_1_iam_permission_boundary.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"has_permission_boundary": false,
		},
	}
	count(result) == 1
}

test_with_boundary if {
	result := cc5_1_iam_permission_boundary.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/alice",
		"data": {
			"user_name": "alice",
			"has_permission_boundary": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc5_1_iam_permission_boundary.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"has_permission_boundary": false},
	}
	count(result) == 0
}
