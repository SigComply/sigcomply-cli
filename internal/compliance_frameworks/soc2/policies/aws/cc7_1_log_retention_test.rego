package sigcomply.soc2.cc7_1_retention_test

import data.sigcomply.soc2.cc7_1_retention

# Test: log group without retention should violate
test_no_retention if {
	result := cc7_1_retention.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/aws/lambda/test",
		"data": {
			"name": "/aws/lambda/test",
			"has_retention": false,
		},
	}
	count(result) == 1
}

# Test: log group with retention should pass
test_has_retention if {
	result := cc7_1_retention.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/aws/cloudtrail",
		"data": {
			"name": "/aws/cloudtrail",
			"has_retention": true,
			"retention_days": 365,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_1_retention.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_retention": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc7_1_retention.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:empty",
		"data": {},
	}
	count(result) == 0
}
