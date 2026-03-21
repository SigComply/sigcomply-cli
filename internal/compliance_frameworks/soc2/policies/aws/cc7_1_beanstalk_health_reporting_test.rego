package sigcomply.soc2.cc7_1_beanstalk_health_reporting_test

import data.sigcomply.soc2.cc7_1_beanstalk_health_reporting

test_no_enhanced_health_reporting if {
	result := cc7_1_beanstalk_health_reporting.violations with input as {
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

test_enhanced_health_reporting_enabled if {
	result := cc7_1_beanstalk_health_reporting.violations with input as {
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
	result := cc7_1_beanstalk_health_reporting.violations with input as {
		"resource_type": "aws:ecs:cluster",
		"resource_id": "arn:aws:ecs:us-east-1:123:cluster/my-cluster",
		"data": {"enhanced_health_reporting": false},
	}
	count(result) == 0
}
