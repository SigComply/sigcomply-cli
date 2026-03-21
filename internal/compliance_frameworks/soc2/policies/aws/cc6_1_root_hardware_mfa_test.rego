package sigcomply.soc2.cc6_1_root_hardware_mfa_test

import data.sigcomply.soc2.cc6_1_root_hardware_mfa

# Test: virtual MFA on root should violate
test_virtual_mfa if {
	result := cc6_1_root_hardware_mfa.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123:root",
		"data": {
			"mfa_enabled": true,
			"hardware_mfa": false,
		},
	}
	count(result) == 1
}

# Test: hardware MFA on root should pass
test_hardware_mfa if {
	result := cc6_1_root_hardware_mfa.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123:root",
		"data": {
			"mfa_enabled": true,
			"hardware_mfa": true,
		},
	}
	count(result) == 0
}

# Test: no MFA at all should not trigger (separate policy handles this)
test_no_mfa if {
	result := cc6_1_root_hardware_mfa.violations with input as {
		"resource_type": "aws:iam:root-account",
		"resource_id": "arn:aws:iam::123:root",
		"data": {
			"mfa_enabled": false,
			"hardware_mfa": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_root_hardware_mfa.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"mfa_enabled": true, "hardware_mfa": false},
	}
	count(result) == 0
}
