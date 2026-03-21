package sigcomply.soc2.cc7_1_mq_audit_logs_test

import data.sigcomply.soc2.cc7_1_mq_audit_logs

# Test: broker without audit logging should violate
test_audit_logs_disabled if {
	result := cc7_1_mq_audit_logs.violations with input as {
		"resource_type": "aws:mq:broker",
		"resource_id": "arn:aws:mq:us-east-1:123456789012:broker:MyBroker:b-1234",
		"data": {
			"broker_name": "MyBroker",
			"arn": "arn:aws:mq:us-east-1:123456789012:broker:MyBroker:b-1234",
			"audit_logs_enabled": false,
			"auto_minor_version_upgrade": true,
		},
	}
	count(result) == 1
}

# Test: broker with audit logging should pass
test_audit_logs_enabled if {
	result := cc7_1_mq_audit_logs.violations with input as {
		"resource_type": "aws:mq:broker",
		"resource_id": "arn:aws:mq:us-east-1:123456789012:broker:MyBroker:b-1234",
		"data": {
			"broker_name": "MyBroker",
			"arn": "arn:aws:mq:us-east-1:123456789012:broker:MyBroker:b-1234",
			"audit_logs_enabled": true,
			"auto_minor_version_upgrade": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := cc7_1_mq_audit_logs.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"audit_logs_enabled": false},
	}
	count(result) == 0
}
