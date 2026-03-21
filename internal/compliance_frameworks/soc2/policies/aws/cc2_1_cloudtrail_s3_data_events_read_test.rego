package sigcomply.soc2.cc2_1_cloudtrail_s3_data_events_read_test

import data.sigcomply.soc2.cc2_1_cloudtrail_s3_data_events_read

test_no_data_events if {
	result := cc2_1_cloudtrail_s3_data_events_read.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/test",
		"data": {"name": "test", "has_s3_data_events": false},
	}
	count(result) == 1
}

test_data_events_enabled if {
	result := cc2_1_cloudtrail_s3_data_events_read.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/test",
		"data": {"name": "test", "has_s3_data_events": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc2_1_cloudtrail_s3_data_events_read.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc2_1_cloudtrail_s3_data_events_read.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
