package sigcomply.soc2.cc7_1_cloudwatch_alarms_test

import data.sigcomply.soc2.cc7_1_cloudwatch_alarms

test_alarms_not_configured if {
	result := cc7_1_cloudwatch_alarms.violations with input as {
		"resource_type": "aws:cloudwatch:alarm-config",
		"resource_id": "arn:aws:cloudwatch:us-east-1:123:alarm-config",
		"data": {
			"all_critical_alarms_configured": false,
			"has_unauthorized_api_calls": false,
			"has_root_usage": false,
			"has_console_sign_in_failures": false,
		},
	}
	count(result) == 1
}

test_alarms_configured if {
	result := cc7_1_cloudwatch_alarms.violations with input as {
		"resource_type": "aws:cloudwatch:alarm-config",
		"resource_id": "arn:aws:cloudwatch:us-east-1:123:alarm-config",
		"data": {
			"all_critical_alarms_configured": true,
			"has_unauthorized_api_calls": true,
			"has_root_usage": true,
			"has_console_sign_in_failures": true,
		},
	}
	count(result) == 0
}

# Partial alarms: some configured but not all
test_partial_alarms if {
	result := cc7_1_cloudwatch_alarms.violations with input as {
		"resource_type": "aws:cloudwatch:alarm-config",
		"resource_id": "arn:aws:cloudwatch:us-east-1:123:alarm-config",
		"data": {
			"all_critical_alarms_configured": false,
			"has_unauthorized_api_calls": true,
			"has_root_usage": true,
			"has_console_sign_in_failures": false,
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc7_1_cloudwatch_alarms.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"all_critical_alarms_configured": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_cloudwatch_alarms.violations with input as {
		"resource_type": "aws:cloudwatch:alarm-config",
		"resource_id": "arn:aws:cloudwatch:us-east-1:123:alarm-config",
		"data": {},
	}
	count(result) == 0
}
