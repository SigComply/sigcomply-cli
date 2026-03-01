package sigcomply.soc2.cc6_1_root_test

import data.sigcomply.soc2.cc6_1_root

# Test: root account without MFA should violate
test_root_no_mfa if {
	result := cc6_1_root.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123456789012:root",
		"data": {
			"account_mfa_enabled": false,
			"account_access_keys_present": 0,
		},
	}
	count(result) == 1
}

# Test: root account with access keys should violate
test_root_access_keys if {
	result := cc6_1_root.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123456789012:root",
		"data": {
			"account_mfa_enabled": true,
			"account_access_keys_present": 2,
		},
	}
	count(result) == 1
}

# Test: root with MFA and no keys should pass
test_root_secure if {
	result := cc6_1_root.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123456789012:root",
		"data": {
			"account_mfa_enabled": true,
			"account_access_keys_present": 0,
		},
	}
	count(result) == 0
}

# Test: root with both issues should have 2 violations
test_root_both_issues if {
	result := cc6_1_root.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123456789012:root",
		"data": {
			"account_mfa_enabled": false,
			"account_access_keys_present": 1,
		},
	}
	count(result) == 2
}

# Test: wrong resource type should not trigger
test_wrong_resource_type if {
	result := cc6_1_root.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123456789012:user/alice",
		"data": {
			"account_mfa_enabled": false,
		},
	}
	count(result) == 0
}

# Negative: empty data object should not trigger
test_empty_data if {
	result := cc6_1_root.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123456789012:root",
		"data": {},
	}
	count(result) == 0
}

# Negative: missing mfa field should not trigger mfa violation
test_missing_mfa_field if {
	result := cc6_1_root.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123456789012:root",
		"data": {
			"account_access_keys_present": 0,
		},
	}
	count(result) == 0
}

# Negative: missing access keys field should not trigger keys violation
test_missing_keys_field if {
	result := cc6_1_root.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123456789012:root",
		"data": {
			"account_mfa_enabled": true,
		},
	}
	count(result) == 0
}
