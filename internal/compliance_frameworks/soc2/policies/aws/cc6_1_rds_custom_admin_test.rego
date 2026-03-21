package sigcomply.soc2.cc6_1_rds_custom_admin_test

import data.sigcomply.soc2.cc6_1_rds_custom_admin

# Test: default username 'admin' should violate
test_default_admin if {
	result := cc6_1_rds_custom_admin.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"master_username": "admin",
		},
	}
	count(result) == 1
}

# Test: default username 'postgres' should violate
test_default_postgres if {
	result := cc6_1_rds_custom_admin.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:pgdb",
		"data": {
			"db_instance_id": "pgdb",
			"master_username": "postgres",
		},
	}
	count(result) == 1
}

# Test: custom username should pass
test_custom_username if {
	result := cc6_1_rds_custom_admin.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"master_username": "myapp_admin",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_rds_custom_admin.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"master_username": "admin"},
	}
	count(result) == 0
}
