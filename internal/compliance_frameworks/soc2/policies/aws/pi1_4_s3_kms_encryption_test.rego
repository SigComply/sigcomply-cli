package sigcomply.soc2.pi1_4_s3_kms_encryption_test

import data.sigcomply.soc2.pi1_4_s3_kms_encryption

test_aes256_encryption if {
	result := pi1_4_s3_kms_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::mybucket",
		"data": {"name": "mybucket", "encryption_enabled": true, "encryption_algorithm": "AES256"},
	}
	count(result) == 1
}

test_kms_encryption if {
	result := pi1_4_s3_kms_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::mybucket",
		"data": {"name": "mybucket", "encryption_enabled": true, "encryption_algorithm": "aws:kms"},
	}
	count(result) == 0
}

test_no_encryption_no_violation if {
	result := pi1_4_s3_kms_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::mybucket",
		"data": {"name": "mybucket", "encryption_enabled": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_4_s3_kms_encryption.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_4_s3_kms_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
