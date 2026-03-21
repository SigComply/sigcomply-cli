package sigcomply.soc2.cc6_8_lambda_dlq_test

import data.sigcomply.soc2.cc6_8_lambda_dlq

test_no_dlq if {
	result := cc6_8_lambda_dlq.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"name": "my-func",
			"has_dlq": false,
		},
	}
	count(result) == 1
}

test_with_dlq if {
	result := cc6_8_lambda_dlq.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"name": "my-func",
			"has_dlq": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_lambda_dlq.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"has_dlq": false},
	}
	count(result) == 0
}
