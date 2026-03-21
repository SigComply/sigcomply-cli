package sigcomply.soc2.cc6_8_cognito_advanced_security_test

import data.sigcomply.soc2.cc6_8_cognito_advanced_security

test_no_advanced_security if {
	result := cc6_8_cognito_advanced_security.violations with input as {
		"resource_type": "aws:cognito:user-pool",
		"resource_id": "arn:aws:cognito-idp:us-east-1:123:userpool/abc",
		"data": {"name": "mypool", "advanced_security_mode": "OFF"},
	}
	count(result) == 1
}

test_enforced if {
	result := cc6_8_cognito_advanced_security.violations with input as {
		"resource_type": "aws:cognito:user-pool",
		"resource_id": "arn:aws:cognito-idp:us-east-1:123:userpool/abc",
		"data": {"name": "mypool", "advanced_security_mode": "ENFORCED"},
	}
	count(result) == 0
}

test_audit if {
	result := cc6_8_cognito_advanced_security.violations with input as {
		"resource_type": "aws:cognito:user-pool",
		"resource_id": "arn:aws:cognito-idp:us-east-1:123:userpool/abc",
		"data": {"name": "mypool", "advanced_security_mode": "AUDIT"},
	}
	count(result) == 0
}

test_empty_mode if {
	result := cc6_8_cognito_advanced_security.violations with input as {
		"resource_type": "aws:cognito:user-pool",
		"resource_id": "arn:aws:cognito-idp:us-east-1:123:userpool/abc",
		"data": {"name": "mypool", "advanced_security_mode": ""},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc6_8_cognito_advanced_security.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
