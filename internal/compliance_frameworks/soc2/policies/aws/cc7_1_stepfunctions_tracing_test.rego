package sigcomply.soc2.cc7_1_stepfunctions_tracing_test

import data.sigcomply.soc2.cc7_1_stepfunctions_tracing

test_no_tracing if {
	result := cc7_1_stepfunctions_tracing.violations with input as {
		"resource_type": "aws:stepfunctions:state-machine",
		"resource_id": "arn:aws:states:us-east-1:123:stateMachine:myMachine",
		"data": {"name": "myMachine", "tracing_enabled": false},
	}
	count(result) == 1
}

test_tracing_enabled if {
	result := cc7_1_stepfunctions_tracing.violations with input as {
		"resource_type": "aws:stepfunctions:state-machine",
		"resource_id": "arn:aws:states:us-east-1:123:stateMachine:myMachine",
		"data": {"name": "myMachine", "tracing_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_stepfunctions_tracing.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
