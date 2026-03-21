package sigcomply.soc2.cc7_3_guardduty_enabled_test

import data.sigcomply.soc2.cc7_3_guardduty_enabled

test_not_enabled if {
	result := cc7_3_guardduty_enabled.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "guardduty-us-east-1",
		"data": {"enabled": false, "region": "us-east-1"},
	}
	count(result) == 1
}

test_enabled if {
	result := cc7_3_guardduty_enabled.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "guardduty-us-east-1",
		"data": {"enabled": true, "region": "us-east-1"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_3_guardduty_enabled.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_3_guardduty_enabled.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
