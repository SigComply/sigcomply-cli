package sigcomply.soc2.cc6_1_ecs_no_secrets_env_test

import data.sigcomply.soc2.cc6_1_ecs_no_secrets_env

test_secrets_in_env_violation if {
	result := cc6_1_ecs_no_secrets_env.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {"family": "my-task", "has_secrets_in_env_vars": true},
	}
	count(result) == 1
}

test_no_secrets_pass if {
	result := cc6_1_ecs_no_secrets_env.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {"family": "my-task", "has_secrets_in_env_vars": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_1_ecs_no_secrets_env.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {"has_secrets_in_env_vars": true},
	}
	count(result) == 0
}
