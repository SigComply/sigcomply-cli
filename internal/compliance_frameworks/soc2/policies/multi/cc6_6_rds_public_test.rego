package sigcomply.soc2.cc6_6_db_public_test

import data.sigcomply.soc2.cc6_6_db_public

# Test: public RDS should violate
test_rds_public if {
	result := cc6_6_db_public.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {
			"db_instance_id": "dev-db",
			"engine": "mysql",
			"publicly_accessible": true,
		},
	}
	count(result) == 1
}

# Test: private RDS should pass
test_rds_private if {
	result := cc6_6_db_public.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {
			"db_instance_id": "prod-db",
			"engine": "postgres",
			"publicly_accessible": false,
		},
	}
	count(result) == 0
}

# Test: GCP SQL with public IP should violate
test_gcp_sql_public if {
	result := cc6_6_db_public.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/dev-db",
		"data": {
			"name": "dev-db",
			"database_version": "POSTGRES_15",
			"public_ip_enabled": true,
		},
	}
	count(result) == 1
}

# Test: GCP SQL without public IP should pass
test_gcp_sql_private if {
	result := cc6_6_db_public.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/prod-db",
		"data": {
			"name": "prod-db",
			"database_version": "POSTGRES_15",
			"public_ip_enabled": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_db_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"publicly_accessible": true},
	}
	count(result) == 0
}

# Negative: empty data for RDS
test_rds_empty_data if {
	result := cc6_6_db_public.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: empty data for GCP SQL
test_gcp_sql_empty_data if {
	result := cc6_6_db_public.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/empty",
		"data": {},
	}
	count(result) == 0
}
