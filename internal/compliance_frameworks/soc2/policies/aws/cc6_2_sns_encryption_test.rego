package sigcomply.soc2.cc6_2_sns_encryption_test

import data.sigcomply.soc2.cc6_2_sns_encryption

test_not_encrypted if {
	result := cc6_2_sns_encryption.violations with input as {
		"resource_type": "aws:sns:topic",
		"resource_id": "arn:aws:sns:us-east-1:123:my-topic",
		"data": {
			"name": "my-topic",
			"encrypted": false,
		},
	}
	count(result) == 1
}

test_encrypted if {
	result := cc6_2_sns_encryption.violations with input as {
		"resource_type": "aws:sns:topic",
		"resource_id": "arn:aws:sns:us-east-1:123:my-topic",
		"data": {
			"name": "my-topic",
			"encrypted": true,
			"kms_key_id": "arn:aws:kms:us-east-1:123:key/abc",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_sns_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"encrypted": false},
	}
	count(result) == 0
}
