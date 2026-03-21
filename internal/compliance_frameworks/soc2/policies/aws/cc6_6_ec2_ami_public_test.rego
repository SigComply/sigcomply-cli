package sigcomply.soc2.cc6_6_ec2_ami_public_test

import data.sigcomply.soc2.cc6_6_ec2_ami_public

test_public_ami if {
	result := cc6_6_ec2_ami_public.violations with input as {
		"resource_type": "aws:ec2:ami",
		"resource_id": "ami-123",
		"data": {"image_id": "ami-123", "public": true},
	}
	count(result) == 1
}

test_private_ami if {
	result := cc6_6_ec2_ami_public.violations with input as {
		"resource_type": "aws:ec2:ami",
		"resource_id": "ami-123",
		"data": {"image_id": "ami-123", "public": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_ec2_ami_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_ec2_ami_public.violations with input as {
		"resource_type": "aws:ec2:ami",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
