package sigcomply.soc2.a1_2_backup_test

import data.sigcomply.soc2.a1_2_backup

# Test: RDS without backups should violate
test_rds_no_backup if {
	result := a1_2_backup.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {
			"db_instance_id": "dev-db",
			"backup_enabled": false,
			"backup_retention_period": 0,
		},
	}
	count(result) == 1
}

# Test: RDS with backups should pass
test_rds_with_backup if {
	result := a1_2_backup.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {
			"db_instance_id": "prod-db",
			"backup_enabled": true,
			"backup_retention_period": 7,
		},
	}
	count(result) == 0
}

# Test: GCP SQL without backups should violate
test_gcp_sql_no_backup if {
	result := a1_2_backup.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/dev-db",
		"data": {
			"name": "dev-db",
			"backup_enabled": false,
			"pitr_enabled": false,
		},
	}
	count(result) == 1
}

# Test: GCP SQL with backups but no PITR should violate (soft)
test_gcp_sql_no_pitr if {
	result := a1_2_backup.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/staging-db",
		"data": {
			"name": "staging-db",
			"backup_enabled": true,
			"pitr_enabled": false,
		},
	}
	count(result) == 1
}

# Test: GCP SQL with backups and PITR should pass
test_gcp_sql_full_backup if {
	result := a1_2_backup.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/prod-db",
		"data": {
			"name": "prod-db",
			"backup_enabled": true,
			"pitr_enabled": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type should not trigger
test_wrong_resource_type if {
	result := a1_2_backup.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"backup_enabled": false,
		},
	}
	count(result) == 0
}

# Negative: empty data for RDS should not trigger
test_rds_empty_data if {
	result := a1_2_backup.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: empty data for GCP SQL should not trigger
test_gcp_sql_empty_data if {
	result := a1_2_backup.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: GCP SQL with both backup+PITR disabled → only 1 violation (no backup)
test_gcp_sql_no_backup_no_pitr if {
	result := a1_2_backup.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/worst-case",
		"data": {
			"name": "worst-case",
			"backup_enabled": false,
			"pitr_enabled": false,
		},
	}
	# Only backup_enabled==false fires; PITR rule requires backup_enabled==true
	count(result) == 1
}
