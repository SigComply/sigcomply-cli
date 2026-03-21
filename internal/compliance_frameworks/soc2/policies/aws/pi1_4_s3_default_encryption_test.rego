package sigcomply.soc2.pi1_4_s3_default_encryption_test

import data.sigcomply.soc2.pi1_4_s3_default_encryption

test_no_encryption if {
	result := pi1_4_s3_default_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::mybucket",
		"data": {"name": "mybucket", "encryption_enabled": false},
	}
	count(result) == 1
}

test_encryption_enabled if {
	result := pi1_4_s3_default_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::mybucket",
		"data": {"name": "mybucket", "encryption_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_4_s3_default_encryption.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_4_s3_default_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
