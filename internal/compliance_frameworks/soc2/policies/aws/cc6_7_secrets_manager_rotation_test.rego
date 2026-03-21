package sigcomply.soc2.cc6_7_secrets_manager_rotation_test

import data.sigcomply.soc2.cc6_7_secrets_manager_rotation

test_no_rotation if {
	result := cc6_7_secrets_manager_rotation.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:db-password",
		"data": {
			"name": "db-password",
			"rotation_enabled": false,
		},
	}
	count(result) == 1
}

test_with_rotation if {
	result := cc6_7_secrets_manager_rotation.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:db-password",
		"data": {
			"name": "db-password",
			"rotation_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_secrets_manager_rotation.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"rotation_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_secrets_manager_rotation.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:test",
		"data": {},
	}
	count(result) == 0
}
