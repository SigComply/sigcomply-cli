package sigcomply.soc2.cc7_1_s3_access_logging_test

import data.sigcomply.soc2.cc7_1_s3_access_logging

# Test: logging disabled should violate
test_logging_disabled if {
	result := cc7_1_s3_access_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"logging_enabled": false,
		},
	}
	count(result) == 1
}

# Test: logging enabled should pass
test_logging_enabled if {
	result := cc7_1_s3_access_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"logging_enabled": true,
			"logging_target_bucket": "log-bucket",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_1_s3_access_logging.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:::db",
		"data": {"logging_enabled": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc7_1_s3_access_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {},
	}
	count(result) == 0
}
