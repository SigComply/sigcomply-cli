package sigcomply.soc2.cc6_7_tls_minimum_test

import data.sigcomply.soc2.cc6_7_tls_minimum

# Test: ELB with TLS 1.2 policy should pass
test_elb_tls12_policy if {
	result := cc6_7_tls_minimum.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		"data": {
			"name": "my-alb",
			"listeners": [
				{"protocol": "HTTPS", "port": 443, "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06"},
			],
		},
	}
	count(result) == 0
}

# Test: ELB with old TLS policy should violate
test_elb_old_tls_policy if {
	result := cc6_7_tls_minimum.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/old-alb/def",
		"data": {
			"name": "old-alb",
			"listeners": [
				{"protocol": "HTTPS", "port": 443, "ssl_policy": "ELBSecurityPolicy-2016-08"},
			],
		},
	}
	count(result) == 1
}

# Test: ELB listener without SSL policy (HTTP) should pass
test_elb_no_ssl_policy if {
	result := cc6_7_tls_minimum.violations with input as {
		"resource_type": "aws:elbv2:load-balancer",
		"resource_id": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/http-alb/ghi",
		"data": {
			"name": "http-alb",
			"listeners": [
				{"protocol": "HTTP", "port": 80, "ssl_policy": ""},
			],
		},
	}
	count(result) == 0
}

# Test: CloudFront with TLS 1.2 should pass
test_cloudfront_tls12 if {
	result := cc6_7_tls_minimum.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {
			"domain_name": "d123.cloudfront.net",
			"minimum_protocol_version": "TLSv1.2_2021",
		},
	}
	count(result) == 0
}

# Test: CloudFront with old TLS should violate
test_cloudfront_old_tls if {
	result := cc6_7_tls_minimum.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/DEF",
		"data": {
			"domain_name": "d456.cloudfront.net",
			"minimum_protocol_version": "TLSv1",
		},
	}
	count(result) == 1
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_7_tls_minimum.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"minimum_protocol_version": "TLSv1"},
	}
	count(result) == 0
}
