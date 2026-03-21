package sigcomply.soc2.cc7_2_guardduty_alerting_test

import data.sigcomply.soc2.cc7_2_guardduty_alerting

# Test: has GuardDuty rule with SNS target should pass
test_has_rule if {
	result := cc7_2_guardduty_alerting.violations with input as {
		"resource_type": "aws:eventbridge:guardduty-alert",
		"resource_id": "arn:aws:events:us-east-1:123:guardduty-alert",
		"data": {
			"has_guardduty_rule": true,
			"rule_count": 1,
			"target_types": ["SNS"],
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Test: no GuardDuty rule should violate
test_no_rule if {
	result := cc7_2_guardduty_alerting.violations with input as {
		"resource_type": "aws:eventbridge:guardduty-alert",
		"resource_id": "arn:aws:events:us-east-1:123:guardduty-alert",
		"data": {
			"has_guardduty_rule": false,
			"rule_count": 0,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_2_guardduty_alerting.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_guardduty_rule": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc7_2_guardduty_alerting.violations with input as {
		"resource_type": "aws:eventbridge:guardduty-alert",
		"resource_id": "arn:aws:events:us-east-1:123:guardduty-alert",
		"data": {},
	}
	count(result) == 0
}
