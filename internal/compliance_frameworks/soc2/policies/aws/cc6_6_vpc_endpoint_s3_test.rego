package sigcomply.soc2.cc6_6_vpc_endpoint_s3_test

import data.sigcomply.soc2.cc6_6_vpc_endpoint_s3

# Test: no S3 endpoint should violate
test_no_s3_endpoint if {
	result := cc6_6_vpc_endpoint_s3.violations with input as {
		"resource_type": "aws:ec2:vpc-endpoint-status",
		"resource_id": "arn:aws:ec2:us-east-1:123:vpc-endpoint-status",
		"data": {
			"has_s3_endpoint": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Test: S3 endpoint present should pass
test_has_s3_endpoint if {
	result := cc6_6_vpc_endpoint_s3.violations with input as {
		"resource_type": "aws:ec2:vpc-endpoint-status",
		"resource_id": "arn:aws:ec2:us-east-1:123:vpc-endpoint-status",
		"data": {
			"has_s3_endpoint": true,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_vpc_endpoint_s3.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "arn:aws:ec2::123:vpc/vpc-1",
		"data": {
			"has_s3_endpoint": false,
		},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_6_vpc_endpoint_s3.violations with input as {
		"resource_type": "aws:ec2:vpc-endpoint-status",
		"resource_id": "arn:aws:ec2:us-east-1:123:vpc-endpoint-status",
		"data": {},
	}
	count(result) == 0
}
