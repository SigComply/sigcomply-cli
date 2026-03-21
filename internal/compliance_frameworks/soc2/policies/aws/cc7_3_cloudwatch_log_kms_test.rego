package sigcomply.soc2.cc7_3_cloudwatch_log_kms_test

import data.sigcomply.soc2.cc7_3_cloudwatch_log_kms

test_no_kms if {
	result := cc7_3_cloudwatch_log_kms.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/test",
		"data": {"name": "/test", "kms_key_id": ""},
	}
	count(result) == 1
}

test_kms_enabled if {
	result := cc7_3_cloudwatch_log_kms.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/test",
		"data": {"name": "/test", "kms_key_id": "arn:aws:kms:us-east-1:123:key/abc"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_3_cloudwatch_log_kms.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_3_cloudwatch_log_kms.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
