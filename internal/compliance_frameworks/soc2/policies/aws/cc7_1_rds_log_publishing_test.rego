package sigcomply.soc2.cc7_1_rds_log_publishing_test

import data.sigcomply.soc2.cc7_1_rds_log_publishing

# Test: no log publishing should violate
test_no_log_publishing if {
	result := cc7_1_rds_log_publishing.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"engine": "mysql",
			"enabled_cloudwatch_logs": false,
		},
	}
	count(result) == 1
}

# Test: log publishing enabled should pass
test_log_publishing_enabled if {
	result := cc7_1_rds_log_publishing.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"engine": "mysql",
			"enabled_cloudwatch_logs": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_1_rds_log_publishing.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled_cloudwatch_logs": false},
	}
	count(result) == 0
}
