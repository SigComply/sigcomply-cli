package sigcomply.soc2.cc6_2_cloudtrail_encryption_test

import data.sigcomply.soc2.cc6_2_cloudtrail_encryption

# Test: trail without KMS encryption should violate
test_no_kms_encryption if {
	result := cc6_2_cloudtrail_encryption.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {
			"name": "my-trail",
			"kms_key_id": "",
		},
	}
	count(result) == 1
}

# Test: trail with KMS encryption should pass
test_kms_encrypted if {
	result := cc6_2_cloudtrail_encryption.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
		"data": {
			"name": "my-trail",
			"kms_key_id": "arn:aws:kms:us-east-1:123:key/abc-123",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_cloudtrail_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"kms_key_id": ""},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_cloudtrail_encryption.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/empty",
		"data": {},
	}
	count(result) == 0
}
