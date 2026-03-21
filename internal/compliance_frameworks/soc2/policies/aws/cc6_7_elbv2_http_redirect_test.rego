package sigcomply.soc2.cc6_7_elbv2_http_redirect_test

import data.sigcomply.soc2.cc6_7_elbv2_http_redirect

test_no_redirect if {
	result := cc6_7_elbv2_http_redirect.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/123",
		"data": {"name": "my-alb", "type": "application", "has_http_to_https_redirect": false, "https_enforced": false},
	}
	count(result) == 1
}

test_has_redirect if {
	result := cc6_7_elbv2_http_redirect.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/123",
		"data": {"name": "my-alb", "type": "application", "has_http_to_https_redirect": true, "https_enforced": false},
	}
	count(result) == 0
}

test_https_enforced if {
	result := cc6_7_elbv2_http_redirect.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/123",
		"data": {"name": "my-alb", "type": "application", "has_http_to_https_redirect": false, "https_enforced": true},
	}
	count(result) == 0
}

test_nlb_not_applicable if {
	result := cc6_7_elbv2_http_redirect.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/net/my-nlb/123",
		"data": {"name": "my-nlb", "type": "network", "has_http_to_https_redirect": false, "https_enforced": false},
	}
	count(result) == 0
}
