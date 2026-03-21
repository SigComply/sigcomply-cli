package sigcomply.soc2.cc6_6_sagemaker_vpc_test

import data.sigcomply.soc2.cc6_6_sagemaker_vpc

# Test: notebook without subnet (no custom VPC) should violate
test_no_custom_vpc if {
	result := cc6_6_sagemaker_vpc.violations with input as {
		"resource_type": "aws:sagemaker:notebook",
		"resource_id": "arn:aws:sagemaker:us-east-1:123:notebook-instance/dev-notebook",
		"data": {
			"name": "dev-notebook",
			"subnet_id": "",
		},
	}
	count(result) == 1
}

# Test: notebook with subnet (custom VPC) should pass
test_custom_vpc if {
	result := cc6_6_sagemaker_vpc.violations with input as {
		"resource_type": "aws:sagemaker:notebook",
		"resource_id": "arn:aws:sagemaker:us-east-1:123:notebook-instance/prod-notebook",
		"data": {
			"name": "prod-notebook",
			"subnet_id": "subnet-abc123",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_sagemaker_vpc.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2:us-east-1:123:instance/i-1234",
		"data": {"subnet_id": ""},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_6_sagemaker_vpc.violations with input as {
		"resource_type": "aws:sagemaker:notebook",
		"resource_id": "arn:aws:sagemaker:us-east-1:123:notebook-instance/empty",
		"data": {},
	}
	count(result) == 0
}
