package sigcomply.soc2.pi1_5_backup_vault_encrypted_test

import data.sigcomply.soc2.pi1_5_backup_vault_encrypted

test_no_kms if {
	result := pi1_5_backup_vault_encrypted.violations with input as {
		"resource_type": "aws:backup:vault",
		"resource_id": "arn:aws:backup:us-east-1:123:backup-vault:default",
		"data": {"kms_key_configured": false},
	}
	count(result) == 1
}

test_kms_configured if {
	result := pi1_5_backup_vault_encrypted.violations with input as {
		"resource_type": "aws:backup:vault",
		"resource_id": "arn:aws:backup:us-east-1:123:backup-vault:default",
		"data": {"kms_key_configured": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_5_backup_vault_encrypted.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_5_backup_vault_encrypted.violations with input as {
		"resource_type": "aws:backup:vault",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
