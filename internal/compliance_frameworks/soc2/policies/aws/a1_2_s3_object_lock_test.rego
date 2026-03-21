package sigcomply.soc2.a1_2_s3_object_lock_test

import data.sigcomply.soc2.a1_2_s3_object_lock

test_object_lock_disabled if {
	result := a1_2_s3_object_lock.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"object_lock_enabled": false,
		},
	}
	count(result) == 1
}

test_object_lock_enabled if {
	result := a1_2_s3_object_lock.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"object_lock_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_s3_object_lock.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {"object_lock_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := a1_2_s3_object_lock.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::test",
		"data": {},
	}
	count(result) == 0
}
