package sigcomply.soc2.cc7_1_codebuild_logging_test

import data.sigcomply.soc2.cc7_1_codebuild_logging

# Test: project without logging should violate
test_no_logging if {
	result := cc7_1_codebuild_logging.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/no-logs",
		"data": {
			"name": "no-logs",
			"logging_configured": false,
		},
	}
	count(result) == 1
}

# Test: project with logging should pass
test_logging_configured if {
	result := cc7_1_codebuild_logging.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/with-logs",
		"data": {
			"name": "with-logs",
			"logging_configured": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_1_codebuild_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"logging_configured": false},
	}
	count(result) == 0
}
