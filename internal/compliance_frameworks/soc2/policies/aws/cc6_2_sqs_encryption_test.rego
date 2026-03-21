package sigcomply.soc2.cc6_2_sqs_encryption_test

import data.sigcomply.soc2.cc6_2_sqs_encryption

# Test: no encryption should violate
test_not_encrypted if {
	result := cc6_2_sqs_encryption.violations with input as {
		"resource_type": "aws:sqs:queue",
		"resource_id": "arn:aws:sqs:us-east-1:123:my-queue",
		"data": {
			"name": "my-queue",
			"sse_enabled": false,
			"sqs_managed_encryption": false,
		},
	}
	count(result) == 1
}

# Test: KMS encryption should pass
test_kms_encrypted if {
	result := cc6_2_sqs_encryption.violations with input as {
		"resource_type": "aws:sqs:queue",
		"resource_id": "arn:aws:sqs:us-east-1:123:my-queue",
		"data": {
			"name": "my-queue",
			"sse_enabled": true,
			"sqs_managed_encryption": false,
			"kms_key_id": "arn:aws:kms:us-east-1:123:key/abc",
		},
	}
	count(result) == 0
}

# Test: SQS-managed encryption should pass
test_sqs_managed_encrypted if {
	result := cc6_2_sqs_encryption.violations with input as {
		"resource_type": "aws:sqs:queue",
		"resource_id": "arn:aws:sqs:us-east-1:123:my-queue",
		"data": {
			"name": "my-queue",
			"sse_enabled": false,
			"sqs_managed_encryption": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not trigger
test_wrong_resource_type if {
	result := cc6_2_sqs_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"sse_enabled": false,
			"sqs_managed_encryption": false,
		},
	}
	count(result) == 0
}
