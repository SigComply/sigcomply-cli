package sigcomply.soc2.pi1_5_rds_storage_encrypted_test

import data.sigcomply.soc2.pi1_5_rds_storage_encrypted

test_not_encrypted if {
	result := pi1_5_rds_storage_encrypted.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db/mydb",
		"data": {"db_instance_id": "mydb", "storage_encrypted": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := pi1_5_rds_storage_encrypted.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db/mydb",
		"data": {"db_instance_id": "mydb", "storage_encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_5_rds_storage_encrypted.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_5_rds_storage_encrypted.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
