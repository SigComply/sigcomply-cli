package sigcomply.soc2.cc6_8_ecs_task_privileged_test

import data.sigcomply.soc2.cc6_8_ecs_task_privileged

test_privileged_container if {
	result := cc6_8_ecs_task_privileged.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"has_privileged_container": true,
		},
	}
	count(result) == 1
}

test_no_privileged_container if {
	result := cc6_8_ecs_task_privileged.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"has_privileged_container": false,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_ecs_task_privileged.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_privileged_container": true},
	}
	count(result) == 0
}
