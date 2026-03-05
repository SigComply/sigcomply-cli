package sigcomply.soc2.cc7_2_security_hub_test

import data.sigcomply.soc2.cc7_2_security_hub

test_security_hub_disabled if {
	result := cc7_2_security_hub.violations with input as {
		"resource_type": "aws:securityhub:hub",
		"resource_id": "arn:aws:securityhub:us-east-1:123:hub/default",
		"data": {"enabled": false, "region": "us-east-1"},
	}
	count(result) == 1
}

test_security_hub_enabled if {
	result := cc7_2_security_hub.violations with input as {
		"resource_type": "aws:securityhub:hub",
		"resource_id": "arn:aws:securityhub:us-east-1:123:hub/default",
		"data": {"enabled": true, "region": "us-east-1"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_2_security_hub.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_2_security_hub.violations with input as {
		"resource_type": "aws:securityhub:hub",
		"resource_id": "arn:aws:securityhub:us-east-1:123:hub/default",
		"data": {},
	}
	count(result) == 0
}
