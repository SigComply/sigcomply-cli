package sigcomply.soc2.cc6_6_ecs_task_networking_test

import data.sigcomply.soc2.cc6_6_ecs_task_networking

test_host_network_mode if {
	result := cc6_6_ecs_task_networking.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"network_mode": "host",
		},
	}
	count(result) == 1
}

test_awsvpc_network_mode if {
	result := cc6_6_ecs_task_networking.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"network_mode": "awsvpc",
		},
	}
	count(result) == 0
}

test_bridge_network_mode if {
	result := cc6_6_ecs_task_networking.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"network_mode": "bridge",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_ecs_task_networking.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"network_mode": "host"},
	}
	count(result) == 0
}
