package sigcomply.soc2.cc6_1_ecs_no_execute_command_test

import data.sigcomply.soc2.cc6_1_ecs_no_execute_command

test_execute_command_enabled if {
	result := cc6_1_ecs_no_execute_command.violations with input as {
		"resource_type": "aws:ecs:cluster",
		"resource_id": "arn:aws:ecs:us-east-1:123:cluster/mycluster",
		"data": {"name": "mycluster", "execute_command_enabled": true},
	}
	count(result) == 1
}

test_execute_command_disabled if {
	result := cc6_1_ecs_no_execute_command.violations with input as {
		"resource_type": "aws:ecs:cluster",
		"resource_id": "arn:aws:ecs:us-east-1:123:cluster/mycluster",
		"data": {"name": "mycluster", "execute_command_enabled": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_1_ecs_no_execute_command.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
