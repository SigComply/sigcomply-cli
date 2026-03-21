package sigcomply.soc2.a1_2_kinesis_retention_test

import data.sigcomply.soc2.a1_2_kinesis_retention

test_retention_too_short if {
	result := a1_2_kinesis_retention.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream",
		"data": {"stream_name": "my-stream", "arn": "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream", "encrypted": true, "retention_hours": 24},
	}
	count(result) == 1
}

test_retention_sufficient if {
	result := a1_2_kinesis_retention.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream",
		"data": {"stream_name": "my-stream", "arn": "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream", "encrypted": true, "retention_hours": 168},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_kinesis_retention.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"stream_name": "my-stream", "retention_hours": 24},
	}
	count(result) == 0
}
