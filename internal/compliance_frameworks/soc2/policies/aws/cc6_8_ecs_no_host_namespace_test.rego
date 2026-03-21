package sigcomply.soc2.cc6_8_ecs_no_host_namespace_test

import data.sigcomply.soc2.cc6_8_ecs_no_host_namespace

test_host_pid_violation if {
	result := cc6_8_ecs_no_host_namespace.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {"family": "my-task", "has_host_pid_mode": true},
	}
	count(result) == 1
}

test_no_host_pid_pass if {
	result := cc6_8_ecs_no_host_namespace.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {"family": "my-task", "has_host_pid_mode": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_ecs_no_host_namespace.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {"has_host_pid_mode": true},
	}
	count(result) == 0
}
