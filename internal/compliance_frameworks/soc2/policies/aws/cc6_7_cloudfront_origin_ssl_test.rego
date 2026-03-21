package sigcomply.soc2.cc6_7_cloudfront_origin_ssl_test

import data.sigcomply.soc2.cc6_7_cloudfront_origin_ssl

test_http_only_violation if {
	result := cc6_7_cloudfront_origin_ssl.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "origin_protocol_policy": "http-only"},
	}
	count(result) == 1
}

test_https_only_pass if {
	result := cc6_7_cloudfront_origin_ssl.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "origin_protocol_policy": "https-only"},
	}
	count(result) == 0
}

test_match_viewer_pass if {
	result := cc6_7_cloudfront_origin_ssl.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "origin_protocol_policy": "match-viewer"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_cloudfront_origin_ssl.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"origin_protocol_policy": "http-only"},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_cloudfront_origin_ssl.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {},
	}
	count(result) == 0
}
