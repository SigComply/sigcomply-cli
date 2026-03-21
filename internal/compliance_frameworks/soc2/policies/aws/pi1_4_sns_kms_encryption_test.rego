package sigcomply.soc2.pi1_4_sns_kms_encryption_test

import data.sigcomply.soc2.pi1_4_sns_kms_encryption

test_no_kms if {
	result := pi1_4_sns_kms_encryption.violations with input as {
		"resource_type": "aws:sns:topic",
		"resource_id": "arn:aws:sns:us-east-1:123:mytopic",
		"data": {"name": "mytopic", "kms_key_id": ""},
	}
	count(result) == 1
}

test_kms_enabled if {
	result := pi1_4_sns_kms_encryption.violations with input as {
		"resource_type": "aws:sns:topic",
		"resource_id": "arn:aws:sns:us-east-1:123:mytopic",
		"data": {"name": "mytopic", "kms_key_id": "arn:aws:kms:us-east-1:123:key/abc"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_4_sns_kms_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_4_sns_kms_encryption.violations with input as {
		"resource_type": "aws:sns:topic",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
