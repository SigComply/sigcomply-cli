package sigcomply.soc2.cc6_8_ecs_task_root_user_test

import data.sigcomply.soc2.cc6_8_ecs_task_root_user

test_runs_as_root if {
	result := cc6_8_ecs_task_root_user.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"runs_as_root": true,
		},
	}
	count(result) == 1
}

test_non_root_user if {
	result := cc6_8_ecs_task_root_user.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"runs_as_root": false,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_ecs_task_root_user.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"runs_as_root": true},
	}
	count(result) == 0
}
