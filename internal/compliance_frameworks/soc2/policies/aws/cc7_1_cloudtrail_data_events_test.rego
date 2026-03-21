package sigcomply.soc2.cc7_1_cloudtrail_data_events_test

import data.sigcomply.soc2.cc7_1_cloudtrail_data_events

# Test: trail with S3 data events should pass
test_has_data_events if {
	result := cc7_1_cloudtrail_data_events.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-1",
				"data": {"has_s3_data_events": true, "has_lambda_data_events": false},
			},
		],
	}
	count(result) == 0
}

# Test: no trail with data events should violate
test_no_data_events if {
	result := cc7_1_cloudtrail_data_events.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-1",
				"data": {"has_s3_data_events": false, "has_lambda_data_events": false},
			},
		],
	}
	count(result) == 1
}

# Test: no trails should violate
test_no_trails if {
	result := cc7_1_cloudtrail_data_events.violations with input as {
		"resources": [],
	}
	count(result) == 1
}
