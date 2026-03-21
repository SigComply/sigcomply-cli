package sigcomply.soc2.cc7_3_cloudwatch_no_cross_account_test

import data.sigcomply.soc2.cc7_3_cloudwatch_no_cross_account

test_cross_account if {
	result := cc7_3_cloudwatch_no_cross_account.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/test",
		"data": {"name": "/test", "has_cross_account_sharing": true},
	}
	count(result) == 1
}

test_no_cross_account if {
	result := cc7_3_cloudwatch_no_cross_account.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/test",
		"data": {"name": "/test", "has_cross_account_sharing": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_3_cloudwatch_no_cross_account.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_3_cloudwatch_no_cross_account.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
