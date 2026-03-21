package sigcomply.soc2.cc7_1_beanstalk_cloudwatch_logs_test

import data.sigcomply.soc2.cc7_1_beanstalk_cloudwatch_logs

test_cloudwatch_logs_disabled if {
	result := cc7_1_beanstalk_cloudwatch_logs.violations with input as {
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

test_cloudwatch_logs_enabled if {
	result := cc7_1_beanstalk_cloudwatch_logs.violations with input as {
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
	result := cc7_1_beanstalk_cloudwatch_logs.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2:us-east-1:123:instance/i-abc123",
		"data": {"cloudwatch_logs_enabled": false},
	}
	count(result) == 0
}
