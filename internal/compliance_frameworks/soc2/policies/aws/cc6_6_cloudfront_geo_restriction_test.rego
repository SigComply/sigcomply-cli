package sigcomply.soc2.cc6_6_cloudfront_geo_restriction_test

import data.sigcomply.soc2.cc6_6_cloudfront_geo_restriction

# Test: geo restriction disabled should violate
test_geo_restriction_disabled if {
	result := cc6_6_cloudfront_geo_restriction.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABCDEF",
		"data": {
			"domain_name": "d123.cloudfront.net",
			"geo_restriction_enabled": false,
		},
	}
	count(result) == 1
}

# Test: geo restriction enabled should pass
test_geo_restriction_enabled if {
	result := cc6_6_cloudfront_geo_restriction.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABCDEF",
		"data": {
			"domain_name": "d123.cloudfront.net",
			"geo_restriction_enabled": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_cloudfront_geo_restriction.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"geo_restriction_enabled": false,
		},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_6_cloudfront_geo_restriction.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABCDEF",
		"data": {},
	}
	count(result) == 0
}
