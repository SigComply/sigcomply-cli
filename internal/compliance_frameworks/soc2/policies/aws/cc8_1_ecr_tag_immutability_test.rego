package sigcomply.soc2.cc8_1_ecr_tag_immutability_test

import data.sigcomply.soc2.cc8_1_ecr_tag_immutability

# Test: mutable tags should violate
test_mutable_tags if {
	result := cc8_1_ecr_tag_immutability.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/my-app",
		"data": {
			"name": "my-app",
			"tag_immutable": false,
		},
	}
	count(result) == 1
}

# Test: immutable tags should pass
test_immutable_tags if {
	result := cc8_1_ecr_tag_immutability.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/my-app",
		"data": {
			"name": "my-app",
			"tag_immutable": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc8_1_ecr_tag_immutability.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"tag_immutable": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc8_1_ecr_tag_immutability.violations with input as {
		"resource_type": "aws:ecr:repository",
		"resource_id": "arn:aws:ecr:us-east-1:123:repository/empty",
		"data": {},
	}
	count(result) == 0
}
