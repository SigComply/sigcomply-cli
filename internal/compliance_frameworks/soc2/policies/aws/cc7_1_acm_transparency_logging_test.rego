package sigcomply.soc2.cc7_1_acm_transparency_logging_test

import data.sigcomply.soc2.cc7_1_acm_transparency_logging

test_logging_disabled if {
	result := cc7_1_acm_transparency_logging.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc-123",
		"data": {"domain_name": "example.com", "transparency_logging_enabled": false},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_1_acm_transparency_logging.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc-123",
		"data": {"domain_name": "example.com", "transparency_logging_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_acm_transparency_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"transparency_logging_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_acm_transparency_logging.violations with input as {
		"resource_type": "aws:acm:certificate",
		"resource_id": "arn:aws:acm:us-east-1:123:certificate/abc-123",
		"data": {},
	}
	count(result) == 0
}
