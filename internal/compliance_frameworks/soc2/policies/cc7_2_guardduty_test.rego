package sigcomply.soc2.cc7_2_guardduty_test

import data.sigcomply.soc2.cc7_2_guardduty

# Test: GuardDuty disabled should violate
test_guardduty_disabled if {
	result := cc7_2_guardduty.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "arn:aws:guardduty:us-east-1:123:detector",
		"data": {
			"enabled": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Test: GuardDuty enabled should pass
test_guardduty_enabled if {
	result := cc7_2_guardduty.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "arn:aws:guardduty:us-east-1:123:detector",
		"data": {
			"enabled": true,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_2_guardduty.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc7_2_guardduty.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "arn:aws:guardduty:us-east-1:123:detector",
		"data": {},
	}
	count(result) == 0
}
