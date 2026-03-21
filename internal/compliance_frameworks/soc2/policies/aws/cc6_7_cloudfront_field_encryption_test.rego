package sigcomply.soc2.cc6_7_cloudfront_field_encryption_test

import data.sigcomply.soc2.cc6_7_cloudfront_field_encryption

test_no_field_encryption if {
	result := cc6_7_cloudfront_field_encryption.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "abc.cloudfront.net", "field_level_encryption_enabled": false},
	}
	count(result) == 1
}

test_field_encryption_enabled if {
	result := cc6_7_cloudfront_field_encryption.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "abc.cloudfront.net", "field_level_encryption_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_cloudfront_field_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_cloudfront_field_encryption.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
