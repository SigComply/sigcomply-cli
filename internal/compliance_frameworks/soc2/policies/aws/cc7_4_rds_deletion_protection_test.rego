package sigcomply.soc2.cc7_4_rds_deletion_protection_test

import data.sigcomply.soc2.cc7_4_rds_deletion_protection

test_no_protection if {
	result := cc7_4_rds_deletion_protection.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db/mydb",
		"data": {"db_instance_id": "mydb", "deletion_protection": false},
	}
	count(result) == 1
}

test_protection_enabled if {
	result := cc7_4_rds_deletion_protection.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db/mydb",
		"data": {"db_instance_id": "mydb", "deletion_protection": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_4_rds_deletion_protection.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_4_rds_deletion_protection.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
