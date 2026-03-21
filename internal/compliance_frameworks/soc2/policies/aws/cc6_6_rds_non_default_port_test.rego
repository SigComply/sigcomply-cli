package sigcomply.soc2.cc6_6_rds_non_default_port_test

import data.sigcomply.soc2.cc6_6_rds_non_default_port

# Test: MySQL on default port should violate
test_mysql_default_port if {
	result := cc6_6_rds_non_default_port.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"engine": "mysql",
			"port": 3306,
		},
	}
	count(result) == 1
}

# Test: PostgreSQL on default port should violate
test_postgres_default_port if {
	result := cc6_6_rds_non_default_port.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:pgdb",
		"data": {
			"db_instance_id": "pgdb",
			"engine": "postgres",
			"port": 5432,
		},
	}
	count(result) == 1
}

# Test: MySQL on custom port should pass
test_mysql_custom_port if {
	result := cc6_6_rds_non_default_port.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"engine": "mysql",
			"port": 13306,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_rds_non_default_port.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"engine": "mysql", "port": 3306},
	}
	count(result) == 0
}
