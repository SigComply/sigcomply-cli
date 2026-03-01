package sigcomply.soc2.cc6_1_password_test

import data.sigcomply.soc2.cc6_1_password

# Test: no password policy configured
test_no_policy if {
	result := cc6_1_password.violations with input as {
		"resource_type": "aws:iam:password-policy",
		"resource_id": "arn:aws:iam::123:account-password-policy",
		"data": {"has_policy": false},
	}
	count(result) == 1
}

# Test: weak password policy (too short, no complexity)
test_weak_policy if {
	result := cc6_1_password.violations with input as {
		"resource_type": "aws:iam:password-policy",
		"resource_id": "arn:aws:iam::123:account-password-policy",
		"data": {
			"has_policy": true,
			"minimum_password_length": 6,
			"require_uppercase_characters": false,
			"require_lowercase_characters": false,
			"require_numbers": false,
			"require_symbols": false,
			"max_password_age": 0,
		},
	}
	# Should have violations for: length, uppercase, lowercase, numbers, symbols, expiration
	count(result) == 6
}

# Test: strong password policy - no violations
test_strong_policy if {
	result := cc6_1_password.violations with input as {
		"resource_type": "aws:iam:password-policy",
		"resource_id": "arn:aws:iam::123:account-password-policy",
		"data": {
			"has_policy": true,
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"max_password_age": 90,
		},
	}
	count(result) == 0
}

# Test: only password length too short
test_length_only if {
	result := cc6_1_password.violations with input as {
		"resource_type": "aws:iam:password-policy",
		"resource_id": "arn:aws:iam::123:account-password-policy",
		"data": {
			"has_policy": true,
			"minimum_password_length": 8,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"max_password_age": 90,
		},
	}
	count(result) == 1
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_password.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {"has_policy": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_1_password.violations with input as {
		"resource_type": "aws:iam:password-policy",
		"resource_id": "arn:aws:iam::123:account-password-policy",
		"data": {},
	}
	count(result) == 0
}

# Negative: boundary — exactly 14 characters should pass
test_boundary_length_14 if {
	result := cc6_1_password.violations with input as {
		"resource_type": "aws:iam:password-policy",
		"resource_id": "arn:aws:iam::123:account-password-policy",
		"data": {
			"has_policy": true,
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"max_password_age": 90,
		},
	}
	count(result) == 0
}
