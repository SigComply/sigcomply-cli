package sigcomply.soc2.cc7_2_rds_event_subscription_test

import data.sigcomply.soc2.cc7_2_rds_event_subscription

# Test: no event subscription should violate
test_not_configured if {
	result := cc7_2_rds_event_subscription.violations with input as {
		"resource_type": "aws:rds:event-subscription",
		"resource_id": "aws-account/rds-events",
		"data": {
			"configured": false,
		},
	}
	count(result) == 1
}

# Test: event subscription configured should pass
test_configured if {
	result := cc7_2_rds_event_subscription.violations with input as {
		"resource_type": "aws:rds:event-subscription",
		"resource_id": "aws-account/rds-events",
		"data": {
			"configured": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_2_rds_event_subscription.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"configured": false},
	}
	count(result) == 0
}
