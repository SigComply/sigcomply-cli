package sigcomply.soc2.cc6_6_default_sg_restrictions_test

import data.sigcomply.soc2.cc6_6_default_sg_restrictions

test_default_sg_with_ingress_rules if {
	result := cc6_6_default_sg_restrictions.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-123",
		"data": {
			"group_id": "sg-123",
			"group_name": "default",
			"vpc_id": "vpc-abc",
			"ingress_rules": [
				{"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr": "0.0.0.0/0"},
			],
		},
	}
	count(result) == 1
}

test_default_sg_empty_rules if {
	result := cc6_6_default_sg_restrictions.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-456",
		"data": {
			"group_id": "sg-456",
			"group_name": "default",
			"vpc_id": "vpc-abc",
			"ingress_rules": [],
		},
	}
	count(result) == 0
}

test_non_default_sg_with_rules if {
	result := cc6_6_default_sg_restrictions.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-789",
		"data": {
			"group_id": "sg-789",
			"group_name": "web-servers",
			"vpc_id": "vpc-abc",
			"ingress_rules": [
				{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"},
			],
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_default_sg_restrictions.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"group_name": "default",
			"ingress_rules": [{"protocol": "tcp"}],
		},
	}
	count(result) == 0
}
