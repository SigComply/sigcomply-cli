package sigcomply.soc2.cc7_1_cloudtrail_cloudwatch_test

import data.sigcomply.soc2.cc7_1_cloudtrail_cloudwatch

test_no_cloudwatch if {
	result := cc7_1_cloudtrail_cloudwatch.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/main",
		"data": {
			"name": "main",
			"cloudwatch_logs_configured": false,
		},
	}
	count(result) == 1
}

test_with_cloudwatch if {
	result := cc7_1_cloudtrail_cloudwatch.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/main",
		"data": {
			"name": "main",
			"cloudwatch_logs_configured": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_cloudtrail_cloudwatch.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"cloudwatch_logs_configured": false,
		},
	}
	count(result) == 0
}
