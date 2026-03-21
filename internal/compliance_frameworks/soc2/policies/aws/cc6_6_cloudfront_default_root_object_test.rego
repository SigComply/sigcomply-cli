package sigcomply.soc2.cc6_6_cloudfront_default_root_object_test

import data.sigcomply.soc2.cc6_6_cloudfront_default_root_object

# Test: empty default root object should violate
test_no_default_root_object if {
	result := cc6_6_cloudfront_default_root_object.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABCDEF",
		"data": {
			"domain_name": "d123.cloudfront.net",
			"default_root_object": "",
		},
	}
	count(result) == 1
}

# Test: default root object set should pass
test_has_default_root_object if {
	result := cc6_6_cloudfront_default_root_object.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABCDEF",
		"data": {
			"domain_name": "d123.cloudfront.net",
			"default_root_object": "index.html",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_cloudfront_default_root_object.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"default_root_object": "",
		},
	}
	count(result) == 0
}

# Negative: empty data (no domain_name means sprintf fails, no violation generated)
test_empty_data if {
	result := cc6_6_cloudfront_default_root_object.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABCDEF",
		"data": {},
	}
	count(result) == 0
}
