package sigcomply.soc2.cc6_8_lambda_concurrency_limit_test

import data.sigcomply.soc2.cc6_8_lambda_concurrency_limit

# Test: function without reserved concurrency (-1) should violate
test_no_concurrency_limit if {
	result := cc6_8_lambda_concurrency_limit.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"name": "my-func",
			"reserved_concurrency": -1,
		},
	}
	count(result) == 1
}

# Test: function with reserved concurrency should pass
test_concurrency_limit_set if {
	result := cc6_8_lambda_concurrency_limit.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"name": "my-func",
			"reserved_concurrency": 100,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_8_lambda_concurrency_limit.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"reserved_concurrency": -1},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_8_lambda_concurrency_limit.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {},
	}
	count(result) == 0
}
