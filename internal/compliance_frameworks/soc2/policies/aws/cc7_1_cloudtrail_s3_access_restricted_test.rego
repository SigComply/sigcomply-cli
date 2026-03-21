package sigcomply.soc2.cc7_1_cloudtrail_s3_access_restricted_test

import data.sigcomply.soc2.cc7_1_cloudtrail_s3_access_restricted

test_no_s3_bucket if {
	result := cc7_1_cloudtrail_s3_access_restricted.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {
			"name": "my-trail",
			"s3_bucket_name": "",
		},
	}
	count(result) == 1
}

test_with_s3_bucket if {
	result := cc7_1_cloudtrail_s3_access_restricted.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {
			"name": "my-trail",
			"s3_bucket_name": "my-cloudtrail-logs",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_cloudtrail_s3_access_restricted.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"s3_bucket_name": ""},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_cloudtrail_s3_access_restricted.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/test",
		"data": {},
	}
	count(result) == 0
}
