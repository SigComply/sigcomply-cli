package sigcomply.soc2.a1_2_rds_multi_az_test

import data.sigcomply.soc2.a1_2_rds_multi_az

# Test: single-AZ RDS should violate
test_single_az if {
	result := a1_2_rds_multi_az.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {
			"db_instance_id": "dev-db",
			"engine": "mysql",
			"multi_az": false,
		},
	}
	count(result) == 1
}

# Test: multi-AZ RDS should pass
test_multi_az if {
	result := a1_2_rds_multi_az.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {
			"db_instance_id": "prod-db",
			"engine": "postgres",
			"multi_az": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := a1_2_rds_multi_az.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"multi_az": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := a1_2_rds_multi_az.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:empty",
		"data": {},
	}
	count(result) == 0
}
