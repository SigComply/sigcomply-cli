package sigcomply.soc2.pi1_3_rds_cloudwatch_logs_test

import data.sigcomply.soc2.pi1_3_rds_cloudwatch_logs

test_no_cloudwatch_logs if {
	result := pi1_3_rds_cloudwatch_logs.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db/mydb",
		"data": {"db_instance_id": "mydb", "enabled_cloudwatch_logs": false},
	}
	count(result) == 1
}

test_cloudwatch_logs_enabled if {
	result := pi1_3_rds_cloudwatch_logs.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db/mydb",
		"data": {"db_instance_id": "mydb", "enabled_cloudwatch_logs": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_3_rds_cloudwatch_logs.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_3_rds_cloudwatch_logs.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
