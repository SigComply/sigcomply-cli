package sigcomply.soc2.cc7_1_rds_enhanced_monitoring_test

import data.sigcomply.soc2.cc7_1_rds_enhanced_monitoring

test_no_monitoring if {
	result := cc7_1_rds_enhanced_monitoring.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {
			"db_instance_id": "prod-db",
			"enhanced_monitoring_enabled": false,
		},
	}
	count(result) == 1
}

test_with_monitoring if {
	result := cc7_1_rds_enhanced_monitoring.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {
			"db_instance_id": "prod-db",
			"enhanced_monitoring_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_rds_enhanced_monitoring.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enhanced_monitoring_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_rds_enhanced_monitoring.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:test",
		"data": {},
	}
	count(result) == 0
}
