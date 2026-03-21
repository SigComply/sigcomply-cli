package sigcomply.soc2.cc6_6_sagemaker_internet_test

import data.sigcomply.soc2.cc6_6_sagemaker_internet

# Test: notebook with direct internet access should violate
test_direct_internet_enabled if {
	result := cc6_6_sagemaker_internet.violations with input as {
		"resource_type": "aws:sagemaker:notebook",
		"resource_id": "arn:aws:sagemaker:us-east-1:123:notebook-instance/dev-notebook",
		"data": {
			"name": "dev-notebook",
			"direct_internet_access": true,
			"root_access": false,
		},
	}
	count(result) == 1
}

# Test: notebook without direct internet access should pass
test_direct_internet_disabled if {
	result := cc6_6_sagemaker_internet.violations with input as {
		"resource_type": "aws:sagemaker:notebook",
		"resource_id": "arn:aws:sagemaker:us-east-1:123:notebook-instance/prod-notebook",
		"data": {
			"name": "prod-notebook",
			"direct_internet_access": false,
			"root_access": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_sagemaker_internet.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2:us-east-1:123:instance/i-1234",
		"data": {"direct_internet_access": true},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_6_sagemaker_internet.violations with input as {
		"resource_type": "aws:sagemaker:notebook",
		"resource_id": "arn:aws:sagemaker:us-east-1:123:notebook-instance/empty",
		"data": {},
	}
	count(result) == 0
}
