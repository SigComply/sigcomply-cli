package sigcomply.soc2.cc6_1_iam_cloudtrail_policy_test

import data.sigcomply.soc2.cc6_1_iam_cloudtrail_policy

test_full_access if {
	result := cc6_1_iam_cloudtrail_policy.violations with input as {
		"resource_type": "aws:iam:policy",
		"resource_id": "arn:aws:iam::123:policy/full-ct",
		"data": {"policy_name": "full-ct", "has_full_cloudtrail_access": true},
	}
	count(result) == 1
}

test_no_full_access if {
	result := cc6_1_iam_cloudtrail_policy.violations with input as {
		"resource_type": "aws:iam:policy",
		"resource_id": "arn:aws:iam::123:policy/readonly-ct",
		"data": {"policy_name": "readonly-ct", "has_full_cloudtrail_access": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_1_iam_cloudtrail_policy.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_1_iam_cloudtrail_policy.violations with input as {
		"resource_type": "aws:iam:policy",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
