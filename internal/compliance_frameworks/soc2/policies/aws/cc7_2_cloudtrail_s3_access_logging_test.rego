package sigcomply.soc2.cc7_2_cloudtrail_s3_access_logging_test

import data.sigcomply.soc2.cc7_2_cloudtrail_s3_access_logging

test_no_logging if {
	result := cc7_2_cloudtrail_s3_access_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::cloudtrail-bucket",
		"data": {"name": "cloudtrail-bucket", "logging_enabled": false},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_2_cloudtrail_s3_access_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::cloudtrail-bucket",
		"data": {"name": "cloudtrail-bucket", "logging_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_2_cloudtrail_s3_access_logging.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_2_cloudtrail_s3_access_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
