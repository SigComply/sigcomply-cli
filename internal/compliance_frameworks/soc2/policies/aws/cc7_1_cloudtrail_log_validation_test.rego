package sigcomply.soc2.cc7_1_cloudtrail_log_validation_test

import data.sigcomply.soc2.cc7_1_cloudtrail_log_validation

# Test: validation disabled should violate
test_validation_disabled if {
	result := cc7_1_cloudtrail_log_validation.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {
			"name": "my-trail",
			"log_file_validation": false,
		},
	}
	count(result) == 1
}

# Test: validation enabled should pass
test_validation_enabled if {
	result := cc7_1_cloudtrail_log_validation.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {
			"name": "my-trail",
			"log_file_validation": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_1_cloudtrail_log_validation.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"log_file_validation": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc7_1_cloudtrail_log_validation.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {},
	}
	count(result) == 0
}
