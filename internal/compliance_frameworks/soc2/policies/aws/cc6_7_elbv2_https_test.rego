package sigcomply.soc2.cc6_7_elbv2_https_test

import data.sigcomply.soc2.cc6_7_elbv2_https

test_https_enforced if {
	result := cc6_7_elbv2_https.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		"data": {"name": "my-alb", "type": "application", "scheme": "internet-facing", "https_enforced": true},
	}
	count(result) == 0
}

test_https_not_enforced if {
	result := cc6_7_elbv2_https.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/http-alb/def",
		"data": {"name": "http-alb", "type": "application", "scheme": "internet-facing", "https_enforced": false},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_7_elbv2_https.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"https_enforced": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_elbv2_https.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		"data": {},
	}
	count(result) == 0
}
