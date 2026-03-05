package sigcomply.soc2.cc6_2_dynamodb_encryption_test

import data.sigcomply.soc2.cc6_2_dynamodb_encryption

test_encryption_disabled if {
	result := cc6_2_dynamodb_encryption.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/users",
		"data": {"name": "users", "sse_enabled": false},
	}
	count(result) == 1
}

test_encryption_enabled if {
	result := cc6_2_dynamodb_encryption.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/users",
		"data": {"name": "users", "sse_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_dynamodb_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"sse_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_dynamodb_encryption.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/users",
		"data": {},
	}
	count(result) == 0
}
