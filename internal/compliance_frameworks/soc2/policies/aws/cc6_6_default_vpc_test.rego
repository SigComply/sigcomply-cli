package sigcomply.soc2.cc6_6_default_vpc_test

import data.sigcomply.soc2.cc6_6_default_vpc

# Test: default VPC should violate
test_default_vpc if {
	result := cc6_6_default_vpc.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "arn:aws:ec2::123:vpc/vpc-default",
		"data": {
			"vpc_id": "vpc-default",
			"is_default": true,
		},
	}
	count(result) == 1
}

# Test: non-default VPC should pass
test_non_default_vpc if {
	result := cc6_6_default_vpc.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "arn:aws:ec2::123:vpc/vpc-custom",
		"data": {
			"vpc_id": "vpc-custom",
			"is_default": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_default_vpc.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"is_default": true},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_6_default_vpc.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "arn:aws:ec2::123:vpc/vpc-1",
		"data": {},
	}
	count(result) == 0
}
