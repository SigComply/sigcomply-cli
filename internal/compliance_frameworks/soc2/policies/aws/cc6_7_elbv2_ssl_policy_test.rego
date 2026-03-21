package sigcomply.soc2.cc6_7_elbv2_ssl_policy_test

import data.sigcomply.soc2.cc6_7_elbv2_ssl_policy

test_insecure_ssl_policy_violation if {
	result := cc6_7_elbv2_ssl_policy.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		"data": {
			"name": "my-alb",
			"type": "application",
			"has_insecure_ssl_policy": true,
		},
	}
	count(result) == 1
}

test_secure_ssl_policy_pass if {
	result := cc6_7_elbv2_ssl_policy.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		"data": {
			"name": "my-alb",
			"type": "application",
			"has_insecure_ssl_policy": false,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_elbv2_ssl_policy.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"has_insecure_ssl_policy": true},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_elbv2_ssl_policy.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/test/xyz",
		"data": {},
	}
	count(result) == 0
}
