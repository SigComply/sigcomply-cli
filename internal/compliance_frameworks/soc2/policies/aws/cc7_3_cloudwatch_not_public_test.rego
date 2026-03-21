package sigcomply.soc2.cc7_3_cloudwatch_not_public_test

import data.sigcomply.soc2.cc7_3_cloudwatch_not_public

test_public if {
	result := cc7_3_cloudwatch_not_public.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/test",
		"data": {"name": "/test", "is_public": true},
	}
	count(result) == 1
}

test_not_public if {
	result := cc7_3_cloudwatch_not_public.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/test",
		"data": {"name": "/test", "is_public": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_3_cloudwatch_not_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_3_cloudwatch_not_public.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
