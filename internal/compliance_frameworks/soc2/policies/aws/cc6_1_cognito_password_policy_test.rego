package sigcomply.soc2.cc6_1_cognito_password_policy_test

import data.sigcomply.soc2.cc6_1_cognito_password_policy

test_weak_password_policy if {
	result := cc6_1_cognito_password_policy.violations with input as {
		"resource_type": "aws:cognito:user-pool",
		"resource_id": "arn:aws:cognito-idp:us-east-1:123:userpool/abc",
		"data": {"name": "mypool", "min_password_length": 8, "require_uppercase": false, "require_lowercase": false, "require_numbers": false, "require_symbols": false},
	}
	count(result) == 5
}

test_strong_password_policy if {
	result := cc6_1_cognito_password_policy.violations with input as {
		"resource_type": "aws:cognito:user-pool",
		"resource_id": "arn:aws:cognito-idp:us-east-1:123:userpool/abc",
		"data": {"name": "mypool", "min_password_length": 14, "require_uppercase": true, "require_lowercase": true, "require_numbers": true, "require_symbols": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_1_cognito_password_policy.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
