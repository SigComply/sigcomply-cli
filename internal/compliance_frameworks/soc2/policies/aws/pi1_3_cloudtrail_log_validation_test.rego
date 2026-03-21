package sigcomply.soc2.pi1_3_cloudtrail_log_validation_test

import data.sigcomply.soc2.pi1_3_cloudtrail_log_validation

test_no_log_validation if {
	result := pi1_3_cloudtrail_log_validation.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/test",
		"data": {"name": "test", "log_file_validation": false},
	}
	count(result) == 1
}

test_log_validation_enabled if {
	result := pi1_3_cloudtrail_log_validation.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/test",
		"data": {"name": "test", "log_file_validation": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_3_cloudtrail_log_validation.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::test",
		"data": {"log_file_validation": false},
	}
	count(result) == 0
}
