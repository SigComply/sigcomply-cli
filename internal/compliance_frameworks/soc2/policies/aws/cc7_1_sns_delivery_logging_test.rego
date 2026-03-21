package sigcomply.soc2.cc7_1_sns_delivery_logging_test

import data.sigcomply.soc2.cc7_1_sns_delivery_logging

test_no_logging if {
	result := cc7_1_sns_delivery_logging.violations with input as {
		"resource_type": "aws:sns:topic",
		"resource_id": "arn:aws:sns:us-east-1:123:mytopic",
		"data": {"name": "mytopic", "delivery_logging_enabled": false},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_1_sns_delivery_logging.violations with input as {
		"resource_type": "aws:sns:topic",
		"resource_id": "arn:aws:sns:us-east-1:123:mytopic",
		"data": {"name": "mytopic", "delivery_logging_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_sns_delivery_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
