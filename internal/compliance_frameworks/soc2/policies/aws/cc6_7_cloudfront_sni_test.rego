package sigcomply.soc2.cc6_7_cloudfront_sni_test

import data.sigcomply.soc2.cc6_7_cloudfront_sni

# Test: no SNI should violate
test_no_sni if {
	result := cc6_7_cloudfront_sni.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/E1234",
		"data": {
			"domain_name": "d123.cloudfront.net",
			"uses_sni": false,
		},
	}
	count(result) == 1
}

# Test: SNI enabled should pass
test_sni_enabled if {
	result := cc6_7_cloudfront_sni.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/E1234",
		"data": {
			"domain_name": "d123.cloudfront.net",
			"uses_sni": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_7_cloudfront_sni.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"uses_sni": false},
	}
	count(result) == 0
}
