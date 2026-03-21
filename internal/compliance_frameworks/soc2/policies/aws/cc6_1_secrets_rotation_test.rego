package sigcomply.soc2.cc6_1_secrets_rotation_test

import data.sigcomply.soc2.cc6_1_secrets_rotation

test_rotation_disabled if {
	result := cc6_1_secrets_rotation.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:test",
		"data": {"name": "test", "rotation_enabled": false},
	}
	count(result) == 1
}

test_rotation_enabled_recent if {
	result := cc6_1_secrets_rotation.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:test",
		"data": {"name": "test", "rotation_enabled": true, "days_since_rotation": 30},
	}
	count(result) == 0
}

test_rotation_enabled_stale if {
	result := cc6_1_secrets_rotation.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:test",
		"data": {"name": "test", "rotation_enabled": true, "days_since_rotation": 120},
	}
	count(result) == 1
}

# Boundary: exactly 90 days should pass (> 90 required to violate)
test_rotation_boundary_90_days if {
	result := cc6_1_secrets_rotation.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:test",
		"data": {"name": "test", "rotation_enabled": true, "days_since_rotation": 90},
	}
	count(result) == 0
}

# Boundary: 91 days should violate
test_rotation_boundary_91_days if {
	result := cc6_1_secrets_rotation.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:test",
		"data": {"name": "test", "rotation_enabled": true, "days_since_rotation": 91},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_1_secrets_rotation.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"rotation_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_1_secrets_rotation.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:test",
		"data": {},
	}
	count(result) == 0
}
