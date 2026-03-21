package sigcomply.soc2.cc6_1_cognito_mfa_test

import data.sigcomply.soc2.cc6_1_cognito_mfa

test_mfa_off if {
	result := cc6_1_cognito_mfa.violations with input as {
		"resource_type": "aws:cognito:user-pool",
		"resource_id": "arn:aws:cognito-idp:us-east-1:123:userpool/abc",
		"data": {"name": "mypool", "mfa_configuration": "OFF"},
	}
	count(result) == 1
}

test_mfa_on if {
	result := cc6_1_cognito_mfa.violations with input as {
		"resource_type": "aws:cognito:user-pool",
		"resource_id": "arn:aws:cognito-idp:us-east-1:123:userpool/abc",
		"data": {"name": "mypool", "mfa_configuration": "ON"},
	}
	count(result) == 0
}

test_mfa_optional if {
	result := cc6_1_cognito_mfa.violations with input as {
		"resource_type": "aws:cognito:user-pool",
		"resource_id": "arn:aws:cognito-idp:us-east-1:123:userpool/abc",
		"data": {"name": "mypool", "mfa_configuration": "OPTIONAL"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_1_cognito_mfa.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
