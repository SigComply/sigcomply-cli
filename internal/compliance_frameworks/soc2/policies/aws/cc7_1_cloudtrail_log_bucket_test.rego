package sigcomply.soc2.cc7_1_cloudtrail_log_bucket_test

import data.sigcomply.soc2.cc7_1_cloudtrail_log_bucket

# Test: no bucket configured should violate
test_no_bucket if {
	result := cc7_1_cloudtrail_log_bucket.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {
			"name": "my-trail",
			"s3_bucket_name": "",
			"kms_key_id": "",
		},
	}
	count(result) == 1
}

# Test: bucket without KMS should violate
test_bucket_no_kms if {
	result := cc7_1_cloudtrail_log_bucket.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {
			"name": "my-trail",
			"s3_bucket_name": "my-log-bucket",
			"kms_key_id": "",
		},
	}
	count(result) == 1
}

# Test: bucket with KMS should pass
test_bucket_with_kms if {
	result := cc7_1_cloudtrail_log_bucket.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {
			"name": "my-trail",
			"s3_bucket_name": "my-log-bucket",
			"kms_key_id": "arn:aws:kms:us-east-1:123:key/abc-123",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_1_cloudtrail_log_bucket.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"name": "test",
			"s3_bucket_name": "",
			"kms_key_id": "",
		},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc7_1_cloudtrail_log_bucket.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {},
	}
	count(result) == 0
}
