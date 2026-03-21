package sigcomply.soc2.cc6_8_beanstalk_managed_updates_test

import data.sigcomply.soc2.cc6_8_beanstalk_managed_updates

test_managed_updates_disabled if {
	result := cc6_8_beanstalk_managed_updates.violations with input as {
		"resource_type": "aws:elasticbeanstalk:environment",
		"resource_id": "arn:aws:elasticbeanstalk:us-east-1:123:environment/my-app/dev-env",
		"data": {
			"environment_name": "dev-env",
			"enhanced_health_reporting": false,
			"managed_updates_enabled": false,
			"cloudwatch_logs_enabled": false,
		},
	}
	count(result) == 1
}

test_managed_updates_enabled if {
	result := cc6_8_beanstalk_managed_updates.violations with input as {
		"resource_type": "aws:elasticbeanstalk:environment",
		"resource_id": "arn:aws:elasticbeanstalk:us-east-1:123:environment/my-app/prod-env",
		"data": {
			"environment_name": "prod-env",
			"enhanced_health_reporting": true,
			"managed_updates_enabled": true,
			"cloudwatch_logs_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_beanstalk_managed_updates.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:test",
		"data": {"managed_updates_enabled": false},
	}
	count(result) == 0
}
