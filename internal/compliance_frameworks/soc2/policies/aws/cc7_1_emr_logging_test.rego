package sigcomply.soc2.cc7_1_emr_logging_test

import data.sigcomply.soc2.cc7_1_emr_logging

# Test: logging disabled should violate
test_logging_disabled if {
	result := cc7_1_emr_logging.violations with input as {
		"resource_type": "aws:emr:cluster",
		"resource_id": "arn:aws:emr:us-east-1:123456789012:cluster/j-1234567890ABC",
		"data": {
			"name": "dev-cluster",
			"id": "j-1234567890ABC",
			"logging_enabled": false,
		},
	}
	count(result) == 1
}

# Test: logging enabled should pass
test_logging_enabled if {
	result := cc7_1_emr_logging.violations with input as {
		"resource_type": "aws:emr:cluster",
		"resource_id": "arn:aws:emr:us-east-1:123456789012:cluster/j-ABCDEF1234567",
		"data": {
			"name": "prod-cluster",
			"id": "j-ABCDEF1234567",
			"logging_enabled": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_1_emr_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"logging_enabled": false},
	}
	count(result) == 0
}
