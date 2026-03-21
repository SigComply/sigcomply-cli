package sigcomply.soc2.c1_2_s3_lifecycle_test

import data.sigcomply.soc2.c1_2_s3_lifecycle

test_no_lifecycle if {
	result := c1_2_s3_lifecycle.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"has_lifecycle_rules": false,
		},
	}
	count(result) == 1
}

test_with_lifecycle if {
	result := c1_2_s3_lifecycle.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"has_lifecycle_rules": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := c1_2_s3_lifecycle.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {"has_lifecycle_rules": false},
	}
	count(result) == 0
}
