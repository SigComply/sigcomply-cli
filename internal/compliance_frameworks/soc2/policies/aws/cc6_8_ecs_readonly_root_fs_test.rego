package sigcomply.soc2.cc6_8_ecs_readonly_root_fs_test

import data.sigcomply.soc2.cc6_8_ecs_readonly_root_fs

test_no_readonly_violation if {
	result := cc6_8_ecs_readonly_root_fs.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {"family": "my-task", "has_readonly_root_filesystem": false},
	}
	count(result) == 1
}

test_readonly_pass if {
	result := cc6_8_ecs_readonly_root_fs.violations with input as {
		"resource_type": "aws:ecs:task-definition",
		"resource_id": "arn:aws:ecs:us-east-1:123:task-definition/my-task:1",
		"data": {"family": "my-task", "has_readonly_root_filesystem": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_ecs_readonly_root_fs.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {"has_readonly_root_filesystem": false},
	}
	count(result) == 0
}
