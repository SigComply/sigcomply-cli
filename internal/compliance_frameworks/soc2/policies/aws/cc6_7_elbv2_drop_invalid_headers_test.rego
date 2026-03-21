package sigcomply.soc2.cc6_7_elbv2_drop_invalid_headers_test

import data.sigcomply.soc2.cc6_7_elbv2_drop_invalid_headers

test_alb_no_drop_invalid_headers if {
	result := cc6_7_elbv2_drop_invalid_headers.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/123",
		"data": {"name": "my-alb", "type": "application", "drop_invalid_headers": false},
	}
	count(result) == 1
}

test_alb_drop_invalid_headers_enabled if {
	result := cc6_7_elbv2_drop_invalid_headers.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/123",
		"data": {"name": "my-alb", "type": "application", "drop_invalid_headers": true},
	}
	count(result) == 0
}

test_nlb_not_applicable if {
	result := cc6_7_elbv2_drop_invalid_headers.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/net/my-nlb/123",
		"data": {"name": "my-nlb", "type": "network", "drop_invalid_headers": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_elbv2_drop_invalid_headers.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"type": "application", "drop_invalid_headers": false},
	}
	count(result) == 0
}
