package sigcomply.soc2.cc7_1_cloudtrail_lambda_data_events_test

import data.sigcomply.soc2.cc7_1_cloudtrail_lambda_data_events

# Test: trail with Lambda data events should pass
test_has_lambda_data_events if {
	result := cc7_1_cloudtrail_lambda_data_events.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-1",
				"data": {"has_lambda_data_events": true, "has_s3_data_events": false},
			},
		],
	}
	count(result) == 0
}

# Test: no trail with Lambda data events should violate
test_no_lambda_data_events if {
	result := cc7_1_cloudtrail_lambda_data_events.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-1",
				"data": {"has_lambda_data_events": false, "has_s3_data_events": true},
			},
		],
	}
	count(result) == 1
}

# Test: no trails should violate
test_no_trails if {
	result := cc7_1_cloudtrail_lambda_data_events.violations with input as {
		"resources": [],
	}
	count(result) == 1
}

# Test: multiple trails, one has Lambda events
test_multiple_trails_one_has_events if {
	result := cc7_1_cloudtrail_lambda_data_events.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-1",
				"data": {"has_lambda_data_events": false},
			},
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-2",
				"data": {"has_lambda_data_events": true},
			},
		],
	}
	count(result) == 0
}
