package sigcomply.soc2.cc3_3_security_hub_standards_test

import data.sigcomply.soc2.cc3_3_security_hub_standards

# Test: both standards enabled should pass
test_both_standards if {
	result := cc3_3_security_hub_standards.violations with input as {
		"resource_type": "aws:securityhub:hub",
		"resource_id": "arn:aws:securityhub:us-east-1:123:hub/default",
		"data": {
			"enabled": true,
			"region": "us-east-1",
			"has_fsbp": true,
			"has_cis": true,
		},
	}
	count(result) == 0
}

# Test: missing FSBP should violate
test_missing_fsbp if {
	result := cc3_3_security_hub_standards.violations with input as {
		"resource_type": "aws:securityhub:hub",
		"resource_id": "arn:aws:securityhub:us-east-1:123:hub/default",
		"data": {
			"enabled": true,
			"region": "us-east-1",
			"has_fsbp": false,
			"has_cis": true,
		},
	}
	count(result) == 1
}

# Test: missing CIS should violate
test_missing_cis if {
	result := cc3_3_security_hub_standards.violations with input as {
		"resource_type": "aws:securityhub:hub",
		"resource_id": "arn:aws:securityhub:us-east-1:123:hub/default",
		"data": {
			"enabled": true,
			"region": "us-east-1",
			"has_fsbp": true,
			"has_cis": false,
		},
	}
	count(result) == 1
}

# Test: hub disabled should violate
test_hub_disabled if {
	result := cc3_3_security_hub_standards.violations with input as {
		"resource_type": "aws:securityhub:hub",
		"resource_id": "arn:aws:securityhub:us-east-1:123:hub/default",
		"data": {
			"enabled": false,
			"region": "us-east-1",
			"has_fsbp": false,
			"has_cis": false,
		},
	}
	count(result) == 1
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc3_3_security_hub_standards.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": false},
	}
	count(result) == 0
}
