package sigcomply.soc2.cc6_8_ec2_managed_by_ssm_test

import data.sigcomply.soc2.cc6_8_ec2_managed_by_ssm

test_not_managed if {
	result := cc6_8_ec2_managed_by_ssm.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "i-123",
		"data": {"instance_id": "i-123", "ssm_managed": false},
	}
	count(result) == 1
}

test_managed if {
	result := cc6_8_ec2_managed_by_ssm.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "i-123",
		"data": {"instance_id": "i-123", "ssm_managed": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_ec2_managed_by_ssm.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_8_ec2_managed_by_ssm.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
