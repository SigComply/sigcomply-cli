package sigcomply.soc2.cc6_6_subnet_no_public_ip_test

import data.sigcomply.soc2.cc6_6_subnet_no_public_ip

# Test: auto-assign public IP enabled should violate
test_public_ip_enabled if {
	result := cc6_6_subnet_no_public_ip.violations with input as {
		"resource_type": "aws:ec2:subnet",
		"resource_id": "arn:aws:ec2::123:subnet/subnet-123",
		"data": {
			"subnet_id": "subnet-123",
			"vpc_id": "vpc-123",
			"availability_zone": "us-east-1a",
			"map_public_ip_on_launch": true,
		},
	}
	count(result) == 1
}

# Test: auto-assign public IP disabled should pass
test_public_ip_disabled if {
	result := cc6_6_subnet_no_public_ip.violations with input as {
		"resource_type": "aws:ec2:subnet",
		"resource_id": "arn:aws:ec2::123:subnet/subnet-456",
		"data": {
			"subnet_id": "subnet-456",
			"vpc_id": "vpc-123",
			"availability_zone": "us-east-1b",
			"map_public_ip_on_launch": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_subnet_no_public_ip.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"map_public_ip_on_launch": true},
	}
	count(result) == 0
}
