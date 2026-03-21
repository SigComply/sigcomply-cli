package sigcomply.soc2.cc6_3_unused_secrets_test

import data.sigcomply.soc2.cc6_3_unused_secrets

# Test: secret unused for 91 days should violate
test_unused_secret if {
	result := cc6_3_unused_secrets.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:old-secret",
		"data": {
			"secret_name": "old-secret",
			"days_since_last_accessed": 91,
		},
	}
	count(result) == 1
}

# Test: recently accessed secret should pass
test_recently_accessed if {
	result := cc6_3_unused_secrets.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:active-secret",
		"data": {
			"secret_name": "active-secret",
			"days_since_last_accessed": 30,
		},
	}
	count(result) == 0
}

# Test: exactly 90 days should pass (threshold is >90)
test_exactly_90_days if {
	result := cc6_3_unused_secrets.violations with input as {
		"resource_type": "aws:secretsmanager:secret",
		"resource_id": "arn:aws:secretsmanager:us-east-1:123:secret:boundary-secret",
		"data": {
			"secret_name": "boundary-secret",
			"days_since_last_accessed": 90,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_3_unused_secrets.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"days_since_last_accessed": 100},
	}
	count(result) == 0
}
