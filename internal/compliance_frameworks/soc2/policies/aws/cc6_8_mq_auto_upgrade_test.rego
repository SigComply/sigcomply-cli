package sigcomply.soc2.cc6_8_mq_auto_upgrade_test

import data.sigcomply.soc2.cc6_8_mq_auto_upgrade

# Test: broker without auto upgrade should violate
test_auto_upgrade_disabled if {
	result := cc6_8_mq_auto_upgrade.violations with input as {
		"resource_type": "aws:mq:broker",
		"resource_id": "arn:aws:mq:us-east-1:123456789012:broker:MyBroker:b-1234",
		"data": {
			"broker_name": "MyBroker",
			"arn": "arn:aws:mq:us-east-1:123456789012:broker:MyBroker:b-1234",
			"audit_logs_enabled": true,
			"auto_minor_version_upgrade": false,
		},
	}
	count(result) == 1
}

# Test: broker with auto upgrade should pass
test_auto_upgrade_enabled if {
	result := cc6_8_mq_auto_upgrade.violations with input as {
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
	result := cc6_8_mq_auto_upgrade.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"auto_minor_version_upgrade": false},
	}
	count(result) == 0
}
