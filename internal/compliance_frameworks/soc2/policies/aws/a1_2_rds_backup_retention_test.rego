package sigcomply.soc2.a1_2_backup_retention_test

import data.sigcomply.soc2.a1_2_backup_retention

# Test: backup enabled with retention=3 should violate
test_low_retention if {
	result := a1_2_backup_retention.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"backup_enabled": true,
			"backup_retention_period": 3,
		},
	}
	count(result) == 1
}

# Test: backup enabled with retention=7 should pass
test_seven_days_retention if {
	result := a1_2_backup_retention.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"backup_enabled": true,
			"backup_retention_period": 7,
		},
	}
	count(result) == 0
}

# Test: backup enabled with retention=14 should pass
test_fourteen_days_retention if {
	result := a1_2_backup_retention.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"backup_enabled": true,
			"backup_retention_period": 14,
		},
	}
	count(result) == 0
}

# Test: backup disabled should not trigger (caught by a1_2_rds_backup policy)
test_backup_disabled if {
	result := a1_2_backup_retention.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"backup_enabled": false,
			"backup_retention_period": 0,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not trigger
test_wrong_resource_type if {
	result := a1_2_backup_retention.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"backup_enabled": true,
			"backup_retention_period": 3,
		},
	}
	count(result) == 0
}

# Test: empty data should not trigger
test_empty_data if {
	result := a1_2_backup_retention.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {},
	}
	count(result) == 0
}
