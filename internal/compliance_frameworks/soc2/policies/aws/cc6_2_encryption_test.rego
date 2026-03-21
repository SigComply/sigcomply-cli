package sigcomply.soc2.cc6_2_test

import data.sigcomply.soc2.cc6_2

# Negative: S3 bucket without encryption should violate
test_not_encrypted if {
	result := cc6_2.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"encryption_enabled": false,
		},
	}
	count(result) == 1
}

# Negative: AES256 encryption without KMS key should produce warning violation
test_aes256_without_kms if {
	result := cc6_2.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"encryption_enabled": true,
			"encryption_algorithm": "AES256",
		},
	}
	count(result) == 1
}

# Positive: KMS encryption should pass
test_kms_encrypted if {
	result := cc6_2.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"encryption_enabled": true,
			"encryption_algorithm": "aws:kms",
			"encryption_key_id": "arn:aws:kms:us-east-1:123:key/abc",
		},
	}
	count(result) == 0
}

# Positive: AES256 with KMS key should pass (no warning)
test_aes256_with_kms_key if {
	result := cc6_2.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"encryption_enabled": true,
			"encryption_algorithm": "AES256",
			"encryption_key_id": "arn:aws:kms:us-east-1:123:key/abc",
		},
	}
	count(result) == 0
}

# Edge: wrong resource type should not trigger
test_wrong_resource_type if {
	result := cc6_2.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"encryption_enabled": false,
		},
	}
	count(result) == 0
}

# Edge: empty data should not trigger
test_empty_data if {
	result := cc6_2.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {},
	}
	count(result) == 0
}
