package sigcomply.soc2.a1_2_backup_vault_lock_test

import data.sigcomply.soc2.a1_2_backup_vault_lock

# Test: no vault lock should violate
test_no_vault_lock if {
	result := a1_2_backup_vault_lock.violations with input as {
		"resource_type": "aws:backup:status",
		"resource_id": "arn:aws:backup:us-east-1:123:status",
		"data": {
			"vault_lock_enabled": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Test: vault lock enabled should pass
test_vault_lock_enabled if {
	result := a1_2_backup_vault_lock.violations with input as {
		"resource_type": "aws:backup:status",
		"resource_id": "arn:aws:backup:us-east-1:123:status",
		"data": {
			"vault_lock_enabled": true,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := a1_2_backup_vault_lock.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"vault_lock_enabled": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := a1_2_backup_vault_lock.violations with input as {
		"resource_type": "aws:backup:status",
		"resource_id": "arn:aws:backup:us-east-1:123:status",
		"data": {},
	}
	count(result) == 0
}
