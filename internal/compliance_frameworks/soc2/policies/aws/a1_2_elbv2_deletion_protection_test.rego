package sigcomply.soc2.a1_2_elbv2_deletion_protection_test

import data.sigcomply.soc2.a1_2_elbv2_deletion_protection

test_deletion_protection_disabled_violation if {
	result := a1_2_elbv2_deletion_protection.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		"data": {
			"name": "my-alb",
			"type": "application",
			"deletion_protection": false,
		},
	}
	count(result) == 1
}

test_deletion_protection_enabled_pass if {
	result := a1_2_elbv2_deletion_protection.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		"data": {
			"name": "my-alb",
			"type": "application",
			"deletion_protection": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_elbv2_deletion_protection.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"deletion_protection": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := a1_2_elbv2_deletion_protection.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/test/xyz",
		"data": {},
	}
	count(result) == 0
}
