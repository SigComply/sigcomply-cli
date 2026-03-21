package sigcomply.soc2.cc6_6_nacl_unrestricted_ingress_test

import data.sigcomply.soc2.cc6_6_nacl_unrestricted_ingress

# Test: unrestricted SSH ingress should violate
test_unrestricted_ssh if {
	result := cc6_6_nacl_unrestricted_ingress.violations with input as {
		"resource_type": "aws:ec2:network-acl",
		"resource_id": "arn:aws:ec2::123:network-acl/acl-123",
		"data": {
			"network_acl_id": "acl-123",
			"vpc_id": "vpc-123",
			"unrestricted_ssh_ingress": true,
			"unrestricted_rdp_ingress": false,
		},
	}
	count(result) == 1
}

# Test: unrestricted RDP ingress should violate
test_unrestricted_rdp if {
	result := cc6_6_nacl_unrestricted_ingress.violations with input as {
		"resource_type": "aws:ec2:network-acl",
		"resource_id": "arn:aws:ec2::123:network-acl/acl-456",
		"data": {
			"network_acl_id": "acl-456",
			"vpc_id": "vpc-123",
			"unrestricted_ssh_ingress": false,
			"unrestricted_rdp_ingress": true,
		},
	}
	count(result) == 1
}

# Test: both unrestricted should have 2 violations
test_both_unrestricted if {
	result := cc6_6_nacl_unrestricted_ingress.violations with input as {
		"resource_type": "aws:ec2:network-acl",
		"resource_id": "arn:aws:ec2::123:network-acl/acl-789",
		"data": {
			"network_acl_id": "acl-789",
			"vpc_id": "vpc-123",
			"unrestricted_ssh_ingress": true,
			"unrestricted_rdp_ingress": true,
		},
	}
	count(result) == 2
}

# Test: restricted should pass
test_restricted if {
	result := cc6_6_nacl_unrestricted_ingress.violations with input as {
		"resource_type": "aws:ec2:network-acl",
		"resource_id": "arn:aws:ec2::123:network-acl/acl-safe",
		"data": {
			"network_acl_id": "acl-safe",
			"vpc_id": "vpc-123",
			"unrestricted_ssh_ingress": false,
			"unrestricted_rdp_ingress": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_nacl_unrestricted_ingress.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"unrestricted_ssh_ingress": true},
	}
	count(result) == 0
}
