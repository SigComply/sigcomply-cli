package sigcomply.soc2.cc7_1_cloudfront_logging_test

import data.sigcomply.soc2.cc7_1_cloudfront_logging

test_logging_disabled_violation if {
	result := cc7_1_cloudfront_logging.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "logging_enabled": false},
	}
	count(result) == 1
}

test_logging_enabled_pass if {
	result := cc7_1_cloudfront_logging.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "logging_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_cloudfront_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"logging_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_cloudfront_logging.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {},
	}
	count(result) == 0
}
