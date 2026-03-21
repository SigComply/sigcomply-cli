package sigcomply.soc2.cc6_1_kms_scheduled_deletion_test

import data.sigcomply.soc2.cc6_1_kms_scheduled_deletion

# Test: key pending deletion should violate
test_pending_deletion if {
	result := cc6_1_kms_scheduled_deletion.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {
			"key_id": "abc",
			"key_state": "PendingDeletion",
		},
	}
	count(result) == 1
}

# Test: enabled key should pass
test_enabled_key if {
	result := cc6_1_kms_scheduled_deletion.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {
			"key_id": "abc",
			"key_state": "Enabled",
		},
	}
	count(result) == 0
}

# Test: disabled key should pass
test_disabled_key if {
	result := cc6_1_kms_scheduled_deletion.violations with input as {
		"resource_type": "aws:kms:key",
		"resource_id": "arn:aws:kms:us-east-1:123:key/abc",
		"data": {
			"key_id": "abc",
			"key_state": "Disabled",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_kms_scheduled_deletion.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"key_state": "PendingDeletion"},
	}
	count(result) == 0
}
