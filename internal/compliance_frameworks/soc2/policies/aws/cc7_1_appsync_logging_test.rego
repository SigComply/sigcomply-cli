package sigcomply.soc2.cc7_1_appsync_logging_test

import data.sigcomply.soc2.cc7_1_appsync_logging

test_no_logging if {
	result := cc7_1_appsync_logging.violations with input as {
		"resource_type": "aws:appsync:api",
		"resource_id": "arn:aws:appsync:us-east-1:123:apis/abc",
		"data": {"name": "myapi", "logging_enabled": false},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_1_appsync_logging.violations with input as {
		"resource_type": "aws:appsync:api",
		"resource_id": "arn:aws:appsync:us-east-1:123:apis/abc",
		"data": {"name": "myapi", "logging_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_appsync_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_appsync_logging.violations with input as {
		"resource_type": "aws:appsync:api",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
