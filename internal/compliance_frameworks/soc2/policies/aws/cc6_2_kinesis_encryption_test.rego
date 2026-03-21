package sigcomply.soc2.cc6_2_kinesis_encryption_test

import data.sigcomply.soc2.cc6_2_kinesis_encryption

test_encryption_disabled if {
	result := cc6_2_kinesis_encryption.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream",
		"data": {"stream_name": "my-stream", "arn": "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream", "encrypted": false, "retention_hours": 24},
	}
	count(result) == 1
}

test_encryption_enabled if {
	result := cc6_2_kinesis_encryption.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream",
		"data": {"stream_name": "my-stream", "arn": "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream", "encrypted": true, "retention_hours": 24},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_kinesis_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"stream_name": "my-stream", "encrypted": false},
	}
	count(result) == 0
}
