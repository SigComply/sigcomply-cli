package sigcomply.soc2.cc6_7_db_ssl_test

import data.sigcomply.soc2.cc6_7_db_ssl

# Test: RDS without SSL should violate
test_rds_no_ssl if {
	result := cc6_7_db_ssl.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {
			"db_instance_id": "dev-db",
			"engine": "mysql",
			"force_ssl": false,
		},
	}
	count(result) == 1
}

# Test: RDS with SSL should pass
test_rds_ssl if {
	result := cc6_7_db_ssl.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {
			"db_instance_id": "prod-db",
			"engine": "postgres",
			"force_ssl": true,
		},
	}
	count(result) == 0
}

# Test: GCP SQL without SSL should violate
test_gcp_sql_no_ssl if {
	result := cc6_7_db_ssl.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/dev-db",
		"data": {
			"name": "dev-db",
			"require_ssl": false,
		},
	}
	count(result) == 1
}

# Test: GCP SQL with SSL should pass
test_gcp_sql_ssl if {
	result := cc6_7_db_ssl.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/prod-db",
		"data": {
			"name": "prod-db",
			"require_ssl": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_7_db_ssl.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"force_ssl": false},
	}
	count(result) == 0
}

# Negative: empty data for RDS
test_rds_empty_data if {
	result := cc6_7_db_ssl.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: empty data for GCP SQL
test_gcp_sql_empty_data if {
	result := cc6_7_db_ssl.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/empty",
		"data": {},
	}
	count(result) == 0
}
