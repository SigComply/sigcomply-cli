package sigcomply.soc2.a1_2_cloudfront_origin_failover_test

import data.sigcomply.soc2.a1_2_cloudfront_origin_failover

# Test: no origin failover should violate
test_no_origin_failover if {
	result := a1_2_cloudfront_origin_failover.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/E1234",
		"data": {
			"domain_name": "d123.cloudfront.net",
			"has_origin_failover": false,
		},
	}
	count(result) == 1
}

# Test: origin failover configured should pass
test_origin_failover_configured if {
	result := a1_2_cloudfront_origin_failover.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/E1234",
		"data": {
			"domain_name": "d123.cloudfront.net",
			"has_origin_failover": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := a1_2_cloudfront_origin_failover.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_origin_failover": false},
	}
	count(result) == 0
}
