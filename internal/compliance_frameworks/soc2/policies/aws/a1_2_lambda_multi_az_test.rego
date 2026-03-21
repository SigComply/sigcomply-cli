package sigcomply.soc2.a1_2_lambda_multi_az_test

import data.sigcomply.soc2.a1_2_lambda_multi_az

# Test: VPC Lambda in single AZ should violate
test_single_az if {
	result := a1_2_lambda_multi_az.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"function_name": "my-func",
			"vpc_configured": true,
			"availability_zone_count": 1,
		},
	}
	count(result) == 1
}

# Test: VPC Lambda in multi-AZ should pass
test_multi_az if {
	result := a1_2_lambda_multi_az.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"function_name": "my-func",
			"vpc_configured": true,
			"availability_zone_count": 3,
		},
	}
	count(result) == 0
}

# Test: non-VPC Lambda should not trigger
test_no_vpc if {
	result := a1_2_lambda_multi_az.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:no-vpc-func",
		"data": {
			"function_name": "no-vpc-func",
			"vpc_configured": false,
			"availability_zone_count": 0,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := a1_2_lambda_multi_az.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"vpc_configured": true, "availability_zone_count": 1},
	}
	count(result) == 0
}
