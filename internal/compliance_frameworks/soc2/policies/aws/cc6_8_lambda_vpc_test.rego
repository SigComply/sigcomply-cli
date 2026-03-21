package sigcomply.soc2.cc6_8_lambda_vpc_test

import data.sigcomply.soc2.cc6_8_lambda_vpc

test_no_vpc if {
	result := cc6_8_lambda_vpc.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"name": "my-func",
			"vpc_configured": false,
		},
	}
	count(result) == 1
}

test_with_vpc if {
	result := cc6_8_lambda_vpc.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"name": "my-func",
			"vpc_configured": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_lambda_vpc.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"vpc_configured": false},
	}
	count(result) == 0
}
