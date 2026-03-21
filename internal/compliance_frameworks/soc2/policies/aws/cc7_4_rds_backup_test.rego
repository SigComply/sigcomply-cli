package sigcomply.soc2.cc7_4_rds_backup_test

import data.sigcomply.soc2.cc7_4_rds_backup

test_no_backup if {
	result := cc7_4_rds_backup.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db/mydb",
		"data": {"db_instance_id": "mydb", "backup_retention_period": 0},
	}
	count(result) == 1
}

test_backup_configured if {
	result := cc7_4_rds_backup.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db/mydb",
		"data": {"db_instance_id": "mydb", "backup_retention_period": 7},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_4_rds_backup.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_4_rds_backup.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
