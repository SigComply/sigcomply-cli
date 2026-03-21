package sigcomply.soc2.cc6_6_lambda_public_access_test

import data.sigcomply.soc2.cc6_6_lambda_public_access

test_publicly_accessible if {
	result := cc6_6_lambda_public_access.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-api",
		"data": {
			"function_name": "my-api",
			"publicly_accessible": true,
		},
	}
	count(result) == 1
}

test_not_public if {
	result := cc6_6_lambda_public_access.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-api",
		"data": {
			"function_name": "my-api",
			"publicly_accessible": false,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_lambda_public_access.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"publicly_accessible": true},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_lambda_public_access.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:test",
		"data": {},
	}
	count(result) == 0
}
