package sigcomply.soc2.cc6_2_emr_encryption_at_rest_test

import data.sigcomply.soc2.cc6_2_emr_encryption_at_rest

# Test: encryption at rest disabled should violate
test_encryption_at_rest_disabled if {
	result := cc6_2_emr_encryption_at_rest.violations with input as {
		"resource_type": "aws:emr:cluster",
		"resource_id": "arn:aws:emr:us-east-1:123456789012:cluster/j-1234567890ABC",
		"data": {
			"name": "dev-cluster",
			"id": "j-1234567890ABC",
			"encryption_at_rest": false,
		},
	}
	count(result) == 1
}

# Test: encryption at rest enabled should pass
test_encryption_at_rest_enabled if {
	result := cc6_2_emr_encryption_at_rest.violations with input as {
		"resource_type": "aws:emr:cluster",
		"resource_id": "arn:aws:emr:us-east-1:123456789012:cluster/j-ABCDEF1234567",
		"data": {
			"name": "prod-cluster",
			"id": "j-ABCDEF1234567",
			"encryption_at_rest": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_emr_encryption_at_rest.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"encryption_at_rest": false},
	}
	count(result) == 0
}
