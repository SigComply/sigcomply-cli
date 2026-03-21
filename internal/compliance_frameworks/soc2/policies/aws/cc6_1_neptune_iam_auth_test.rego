package sigcomply.soc2.cc6_1_neptune_iam_auth_test

import data.sigcomply.soc2.cc6_1_neptune_iam_auth

# Test: IAM auth disabled should violate
test_iam_auth_disabled if {
	result := cc6_1_neptune_iam_auth.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"iam_auth_enabled": false,
		},
	}
	count(result) == 1
}

# Test: IAM auth enabled should pass
test_iam_auth_enabled if {
	result := cc6_1_neptune_iam_auth.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"iam_auth_enabled": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := cc6_1_neptune_iam_auth.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"iam_auth_enabled": false},
	}
	count(result) == 0
}
