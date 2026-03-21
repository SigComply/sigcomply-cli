package sigcomply.soc2.cc6_2_ecs_task_encryption_test

import data.sigcomply.soc2.cc6_2_ecs_task_encryption

test_efs_no_transit_encryption if {
	result := cc6_2_ecs_task_encryption.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"has_efs_volumes": true,
			"efs_transit_encryption_enabled": false,
		},
	}
	count(result) == 1
}

test_efs_with_transit_encryption if {
	result := cc6_2_ecs_task_encryption.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"has_efs_volumes": true,
			"efs_transit_encryption_enabled": true,
		},
	}
	count(result) == 0
}

test_no_efs_volumes if {
	result := cc6_2_ecs_task_encryption.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {
			"task_definition_arn": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
			"family": "my-task",
			"has_efs_volumes": false,
			"efs_transit_encryption_enabled": false,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_ecs_task_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_efs_volumes": true, "efs_transit_encryption_enabled": false},
	}
	count(result) == 0
}
