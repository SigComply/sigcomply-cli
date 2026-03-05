package sigcomply.soc2.a1_2_rds_deletion_protection_test

import data.sigcomply.soc2.a1_2_rds_deletion_protection

# Test: deletion protection disabled should violate
test_deletion_protection_disabled if {
	result := a1_2_rds_deletion_protection.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {
			"db_instance_id": "prod-db",
			"engine": "postgres",
			"deletion_protection": false,
		},
	}
	count(result) == 1
}

# Test: deletion protection enabled should pass
test_deletion_protection_enabled if {
	result := a1_2_rds_deletion_protection.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {
			"db_instance_id": "prod-db",
			"engine": "postgres",
			"deletion_protection": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := a1_2_rds_deletion_protection.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"deletion_protection": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := a1_2_rds_deletion_protection.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {},
	}
	count(result) == 0
}
