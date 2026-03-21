package sigcomply.soc2.pi1_5_kms_rotation_test

import data.sigcomply.soc2.pi1_5_kms_rotation

test_no_rotation if {
	result := pi1_5_kms_rotation.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {"key_id": "abc", "key_manager": "CUSTOMER", "rotation_enabled": false},
	}
	count(result) == 1
}

test_rotation_enabled if {
	result := pi1_5_kms_rotation.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {"key_id": "abc", "key_manager": "CUSTOMER", "rotation_enabled": true},
	}
	count(result) == 0
}

test_aws_managed_key_no_violation if {
	result := pi1_5_kms_rotation.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {"key_id": "abc", "key_manager": "AWS", "rotation_enabled": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_5_kms_rotation.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_5_kms_rotation.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
