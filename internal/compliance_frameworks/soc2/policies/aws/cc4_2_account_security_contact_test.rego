package sigcomply.soc2.cc4_2_account_security_contact_test

import data.sigcomply.soc2.cc4_2_account_security_contact

# Test: no security contact should violate
test_no_security_contact if {
	result := cc4_2_account_security_contact.violations with input as {
		"resource_type": "aws:account:security-contact",
		"resource_id": "arn:aws:account::123:security-contact",
		"data": {
			"has_security_contact": false,
			"region": "",
		},
	}
	count(result) == 1
}

# Test: security contact configured should pass
test_security_contact_configured if {
	result := cc4_2_account_security_contact.violations with input as {
		"resource_type": "aws:account:security-contact",
		"resource_id": "arn:aws:account::123:security-contact",
		"data": {
			"has_security_contact": true,
			"region": "",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc4_2_account_security_contact.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_security_contact": false},
	}
	count(result) == 0
}
