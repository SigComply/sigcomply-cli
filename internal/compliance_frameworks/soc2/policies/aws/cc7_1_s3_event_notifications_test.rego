package sigcomply.soc2.cc7_1_s3_event_notifications_test

import data.sigcomply.soc2.cc7_1_s3_event_notifications

test_no_notifications if {
	result := cc7_1_s3_event_notifications.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"name": "my-bucket", "event_notifications_configured": false},
	}
	count(result) == 1
}

test_notifications_configured if {
	result := cc7_1_s3_event_notifications.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"name": "my-bucket", "event_notifications_configured": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_s3_event_notifications.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:::db-1",
		"data": {"event_notifications_configured": false},
	}
	count(result) == 0
}
