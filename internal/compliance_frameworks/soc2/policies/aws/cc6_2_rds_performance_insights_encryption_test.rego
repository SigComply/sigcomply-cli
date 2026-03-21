package sigcomply.soc2.cc6_2_rds_performance_insights_encryption_test

import data.sigcomply.soc2.cc6_2_rds_performance_insights_encryption

test_not_encrypted if {
	result := cc6_2_rds_performance_insights_encryption.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {"db_instance_id": "dev-db", "performance_insights_encrypted": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := cc6_2_rds_performance_insights_encryption.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {"db_instance_id": "prod-db", "performance_insights_encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_rds_performance_insights_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"performance_insights_encrypted": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_rds_performance_insights_encryption.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:empty",
		"data": {},
	}
	count(result) == 0
}
