package sigcomply.soc2.a1_2_s3_cross_region_replication_test

import data.sigcomply.soc2.a1_2_s3_cross_region_replication

test_no_replication if {
	result := a1_2_s3_cross_region_replication.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"name": "my-bucket", "replication_enabled": false},
	}
	count(result) == 1
}

test_replication_enabled if {
	result := a1_2_s3_cross_region_replication.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"name": "my-bucket", "replication_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_s3_cross_region_replication.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:::db-1",
		"data": {"replication_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := a1_2_s3_cross_region_replication.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::test",
		"data": {},
	}
	count(result) == 0
}
