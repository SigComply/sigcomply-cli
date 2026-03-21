package sigcomply.soc2.c1_2_kinesis_retention_test

import data.sigcomply.soc2.c1_2_kinesis_retention

test_short_retention if {
	result := c1_2_kinesis_retention.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "arn:aws:kinesis:us-east-1:123:stream/mystream",
		"data": {"stream_name": "mystream", "retention_hours": 24},
	}
	count(result) == 1
}

test_adequate_retention if {
	result := c1_2_kinesis_retention.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "arn:aws:kinesis:us-east-1:123:stream/mystream",
		"data": {"stream_name": "mystream", "retention_hours": 168},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := c1_2_kinesis_retention.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := c1_2_kinesis_retention.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
