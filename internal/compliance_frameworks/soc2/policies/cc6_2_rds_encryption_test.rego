package sigcomply.soc2.cc6_2_rds_test

import data.sigcomply.soc2.cc6_2_rds

# Test: unencrypted RDS should violate
test_rds_not_encrypted if {
	result := cc6_2_rds.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {
			"db_instance_id": "dev-db",
			"engine": "mysql",
			"storage_encrypted": false,
		},
	}
	count(result) == 1
}

# Test: encrypted RDS should pass
test_rds_encrypted if {
	result := cc6_2_rds.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {
			"db_instance_id": "prod-db",
			"engine": "postgres",
			"storage_encrypted": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_rds.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"storage_encrypted": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_rds.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:empty",
		"data": {},
	}
	count(result) == 0
}
