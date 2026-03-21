package sigcomply.soc2.cc6_6_ec2_public_ip_test

import data.sigcomply.soc2.cc6_6_ec2_public_ip

test_instance_with_public_ip if {
	result := cc6_6_ec2_public_ip.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-123",
		"data": {
			"instance_id": "i-123",
			"public_ip": "54.123.45.67",
		},
	}
	count(result) == 1
}

test_instance_without_public_ip if {
	result := cc6_6_ec2_public_ip.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-456",
		"data": {
			"instance_id": "i-456",
			"public_ip": "",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_ec2_public_ip.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"public_ip": "1.2.3.4"},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_ec2_public_ip.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-789",
		"data": {},
	}
	count(result) == 0
}
