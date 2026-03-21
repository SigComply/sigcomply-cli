package sigcomply.soc2.cc7_3_log_retention_test

import data.sigcomply.soc2.cc7_3_log_retention

test_no_retention if {
	result := cc7_3_log_retention.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/test",
		"data": {"name": "/test", "has_retention": false},
	}
	count(result) == 1
}

test_retention_set if {
	result := cc7_3_log_retention.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/test",
		"data": {"name": "/test", "has_retention": true, "retention_days": 90},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_3_log_retention.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_3_log_retention.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
