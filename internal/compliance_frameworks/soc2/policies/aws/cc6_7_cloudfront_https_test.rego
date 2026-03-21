package sigcomply.soc2.cc6_7_cloudfront_https_test

import data.sigcomply.soc2.cc6_7_cloudfront_https

test_http_allowed if {
	result := cc6_7_cloudfront_https.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "https_only": false, "viewer_protocol_policy": "allow-all"},
	}
	count(result) == 1
}

test_https_only if {
	result := cc6_7_cloudfront_https.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "https_only": true, "viewer_protocol_policy": "https-only"},
	}
	count(result) == 0
}

# Redirect to HTTPS still counts as not https_only if the collector flags it
test_redirect_to_https if {
	result := cc6_7_cloudfront_https.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "https_only": false, "viewer_protocol_policy": "redirect-to-https"},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_7_cloudfront_https.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"https_only": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_cloudfront_https.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {},
	}
	count(result) == 0
}
