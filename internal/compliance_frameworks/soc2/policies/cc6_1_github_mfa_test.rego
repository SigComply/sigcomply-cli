package sigcomply.soc2.cc6_1_github_test

import data.sigcomply.soc2.cc6_1_github

# Test: member without 2FA should violate
test_no_2fa if {
	result := cc6_1_github.violations with input as {
		"resource_type": "github:member",
		"resource_id": "org/member/bob",
		"data": {
			"login": "bob",
			"organization": "my-org",
			"two_factor_enabled": false,
		},
	}
	count(result) == 1
}

# Test: member with 2FA should pass
test_with_2fa if {
	result := cc6_1_github.violations with input as {
		"resource_type": "github:member",
		"resource_id": "org/member/alice",
		"data": {
			"login": "alice",
			"organization": "my-org",
			"two_factor_enabled": true,
		},
	}
	count(result) == 0
}

# Test: member with unknown 2FA status should violate
test_unknown_2fa if {
	result := cc6_1_github.violations with input as {
		"resource_type": "github:member",
		"resource_id": "org/member/charlie",
		"data": {
			"login": "charlie",
			"organization": "my-org",
		},
	}
	count(result) == 1
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_github.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {"two_factor_enabled": false},
	}
	count(result) == 0
}

# Negative: empty data (no login or 2FA fields) - sprintf on undefined login causes rule to not match
test_empty_data if {
	result := cc6_1_github.violations with input as {
		"resource_type": "github:member",
		"resource_id": "org/member/empty",
		"data": {},
	}
	count(result) == 0
}
