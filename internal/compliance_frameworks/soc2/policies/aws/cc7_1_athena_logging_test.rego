package sigcomply.soc2.cc7_1_athena_logging_test

import data.sigcomply.soc2.cc7_1_athena_logging

test_no_metrics if {
	result := cc7_1_athena_logging.violations with input as {
		"resource_type": "aws:athena:workgroup",
		"resource_id": "arn:aws:athena:us-east-1:123:workgroup/primary",
		"data": {"name": "primary", "publish_cloudwatch_metrics": false},
	}
	count(result) == 1
}

test_metrics_enabled if {
	result := cc7_1_athena_logging.violations with input as {
		"resource_type": "aws:athena:workgroup",
		"resource_id": "arn:aws:athena:us-east-1:123:workgroup/primary",
		"data": {"name": "primary", "publish_cloudwatch_metrics": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_athena_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_athena_logging.violations with input as {
		"resource_type": "aws:athena:workgroup",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
