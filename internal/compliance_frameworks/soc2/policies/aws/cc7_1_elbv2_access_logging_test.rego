package sigcomply.soc2.cc7_1_elbv2_access_logging_test

import data.sigcomply.soc2.cc7_1_elbv2_access_logging

test_access_logging_disabled if {
	result := cc7_1_elbv2_access_logging.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		"data": {
			"name": "my-alb",
			"type": "application",
			"access_logs_enabled": false,
		},
	}
	count(result) == 1
}

test_access_logging_enabled if {
	result := cc7_1_elbv2_access_logging.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		"data": {
			"name": "my-alb",
			"type": "application",
			"access_logs_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_elbv2_access_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"access_logs_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_elbv2_access_logging.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/test/xyz",
		"data": {},
	}
	count(result) == 0
}
