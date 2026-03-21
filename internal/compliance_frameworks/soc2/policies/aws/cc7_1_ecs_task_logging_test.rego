package sigcomply.soc2.cc7_1_ecs_task_logging_test

import data.sigcomply.soc2.cc7_1_ecs_task_logging

test_logging_not_configured if {
	result := cc7_1_ecs_task_logging.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"logging_configured": false,
		},
	}
	count(result) == 1
}

test_logging_configured if {
	result := cc7_1_ecs_task_logging.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"logging_configured": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_ecs_task_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"logging_configured": false},
	}
	count(result) == 0
}
