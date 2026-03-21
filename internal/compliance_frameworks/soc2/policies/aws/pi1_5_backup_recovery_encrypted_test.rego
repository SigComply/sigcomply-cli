package sigcomply.soc2.pi1_5_backup_recovery_encrypted_test

import data.sigcomply.soc2.pi1_5_backup_recovery_encrypted

test_not_encrypted if {
	result := pi1_5_backup_recovery_encrypted.violations with input as {
		"resource_type": "aws:backup:recovery-point",
		"resource_id": "arn:aws:backup:us-east-1:123:recovery-point/abc",
		"data": {"encrypted": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := pi1_5_backup_recovery_encrypted.violations with input as {
		"resource_type": "aws:backup:recovery-point",
		"resource_id": "arn:aws:backup:us-east-1:123:recovery-point/abc",
		"data": {"encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_5_backup_recovery_encrypted.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_5_backup_recovery_encrypted.violations with input as {
		"resource_type": "aws:backup:recovery-point",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
