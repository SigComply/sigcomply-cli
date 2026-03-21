package sigcomply.soc2.cc6_6_cloudfront_waf_test

import data.sigcomply.soc2.cc6_6_cloudfront_waf

test_waf_disabled_violation if {
	result := cc6_6_cloudfront_waf.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "waf_enabled": false},
	}
	count(result) == 1
}

test_waf_enabled_pass if {
	result := cc6_6_cloudfront_waf.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "waf_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_cloudfront_waf.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"waf_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_cloudfront_waf.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {},
	}
	count(result) == 0
}
