package sigcomply.soc2.cc6_6_ecr_private_repository_test

import data.sigcomply.soc2.cc6_6_ecr_private_repository

# Test: public repository should violate
test_public_repository if {
	result := cc6_6_ecr_private_repository.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/public-app",
		"data": {
			"name": "public-app",
			"is_public": true,
		},
	}
	count(result) == 1
}

# Test: private repository should pass
test_private_repository if {
	result := cc6_6_ecr_private_repository.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/my-app",
		"data": {
			"name": "my-app",
			"is_public": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_ecr_private_repository.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"is_public": true},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_6_ecr_private_repository.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/empty",
		"data": {},
	}
	count(result) == 0
}
