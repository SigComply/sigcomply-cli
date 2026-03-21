package sigcomply.soc2.cc6_8_sagemaker_root_test

import data.sigcomply.soc2.cc6_8_sagemaker_root

# Test: notebook with root access should violate
test_root_access_enabled if {
	result := cc6_8_sagemaker_root.violations with input as {
		"resource_type": "aws:sagemaker:notebook",
		"resource_id": "arn:aws:sagemaker:us-east-1:123:notebook-instance/dev-notebook",
		"data": {
			"name": "dev-notebook",
			"root_access": true,
			"direct_internet_access": false,
		},
	}
	count(result) == 1
}

# Test: notebook without root access should pass
test_root_access_disabled if {
	result := cc6_8_sagemaker_root.violations with input as {
		"resource_type": "aws:sagemaker:notebook",
		"resource_id": "arn:aws:sagemaker:us-east-1:123:notebook-instance/prod-notebook",
		"data": {
			"name": "prod-notebook",
			"root_access": false,
			"direct_internet_access": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_8_sagemaker_root.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2:us-east-1:123:instance/i-1234",
		"data": {"root_access": true},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_8_sagemaker_root.violations with input as {
		"resource_type": "aws:sagemaker:notebook",
		"resource_id": "arn:aws:sagemaker:us-east-1:123:notebook-instance/empty",
		"data": {},
	}
	count(result) == 0
}
