package sigcomply.soc2.cc6_2_cloudwatch_log_encryption_test

import data.sigcomply.soc2.cc6_2_cloudwatch_log_encryption

test_log_group_no_kms_key if {
	result := cc6_2_cloudwatch_log_encryption.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/app/logs",
		"data": {
			"name": "/app/logs",
			"kms_key_id": "",
		},
	}
	count(result) == 1
}

test_log_group_with_kms_key if {
	result := cc6_2_cloudwatch_log_encryption.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:/app/logs",
		"data": {
			"name": "/app/logs",
			"kms_key_id": "arn:aws:kms:us-east-1:123:key/abc-def",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_cloudwatch_log_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"kms_key_id": ""},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_cloudwatch_log_encryption.violations with input as {
		"resource_type": "aws:logs:log-group",
		"resource_id": "arn:aws:logs:us-east-1:123:log-group:test",
		"data": {},
	}
	count(result) == 0
}
