package sigcomply.soc2.pi1_4_kinesis_encryption_test

import data.sigcomply.soc2.pi1_4_kinesis_encryption

test_not_encrypted if {
	result := pi1_4_kinesis_encryption.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "arn:aws:kinesis:us-east-1:123:stream/mystream",
		"data": {"stream_name": "mystream", "encrypted": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := pi1_4_kinesis_encryption.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "arn:aws:kinesis:us-east-1:123:stream/mystream",
		"data": {"stream_name": "mystream", "encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_4_kinesis_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_4_kinesis_encryption.violations with input as {
		"resource_type": "aws:kinesis:stream",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
