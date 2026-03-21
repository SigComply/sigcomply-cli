package sigcomply.soc2.cc7_1_stepfunctions_logging_test

import data.sigcomply.soc2.cc7_1_stepfunctions_logging

# Test: state machine without logging should violate
test_logging_disabled if {
	result := cc7_1_stepfunctions_logging.violations with input as {
		"resource_type": "aws:stepfunctions:state-machine",
		"resource_id": "arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine",
		"data": {
			"name": "MyStateMachine",
			"arn": "arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine",
			"logging_enabled": false,
		},
	}
	count(result) == 1
}

# Test: state machine with logging should pass
test_logging_enabled if {
	result := cc7_1_stepfunctions_logging.violations with input as {
		"resource_type": "aws:stepfunctions:state-machine",
		"resource_id": "arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine",
		"data": {
			"name": "MyStateMachine",
			"arn": "arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine",
			"logging_enabled": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := cc7_1_stepfunctions_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"logging_enabled": false},
	}
	count(result) == 0
}
