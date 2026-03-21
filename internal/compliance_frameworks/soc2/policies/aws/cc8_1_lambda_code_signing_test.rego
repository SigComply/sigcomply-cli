package sigcomply.soc2.cc8_1_lambda_code_signing_test

import data.sigcomply.soc2.cc8_1_lambda_code_signing

# Test: function without code signing should violate
test_no_code_signing if {
	result := cc8_1_lambda_code_signing.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"name": "my-func",
			"code_signing_enabled": false,
		},
	}
	count(result) == 1
}

# Test: function with code signing should pass
test_code_signing_enabled if {
	result := cc8_1_lambda_code_signing.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"name": "my-func",
			"code_signing_enabled": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc8_1_lambda_code_signing.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"code_signing_enabled": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc8_1_lambda_code_signing.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {},
	}
	count(result) == 0
}
