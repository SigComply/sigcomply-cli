package sigcomply.soc2.pi1_5_backup_encrypted_test

import data.sigcomply.soc2.pi1_5_backup_encrypted

test_not_encrypted if {
	result := pi1_5_backup_encrypted.violations with input as {
		"resource_type": "aws:backup:vault",
		"resource_id": "arn:aws:backup:us-east-1:123:backup-vault:default",
		"data": {"encryption_enabled": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := pi1_5_backup_encrypted.violations with input as {
		"resource_type": "aws:backup:vault",
		"resource_id": "arn:aws:backup:us-east-1:123:backup-vault:default",
		"data": {"encryption_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_5_backup_encrypted.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_5_backup_encrypted.violations with input as {
		"resource_type": "aws:backup:vault",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
