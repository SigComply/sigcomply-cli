package sigcomply.soc2.cc6_8_ecs_security_test

import data.sigcomply.soc2.cc6_8_ecs_security

test_insights_disabled if {
	result := cc6_8_ecs_security.violations with input as {
		"resource_type": "aws:ecs:cluster",
		"resource_id": "arn:aws:ecs:us-east-1:123:cluster/prod",
		"data": {"name": "prod", "container_insights_enabled": false},
	}
	count(result) == 1
}

test_insights_enabled if {
	result := cc6_8_ecs_security.violations with input as {
		"resource_type": "aws:ecs:cluster",
		"resource_id": "arn:aws:ecs:us-east-1:123:cluster/prod",
		"data": {"name": "prod", "container_insights_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_ecs_security.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"container_insights_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_8_ecs_security.violations with input as {
		"resource_type": "aws:ecs:cluster",
		"resource_id": "arn:aws:ecs:us-east-1:123:cluster/prod",
		"data": {},
	}
	count(result) == 0
}
