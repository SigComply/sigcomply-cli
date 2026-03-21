package sigcomply.soc2.cc6_6_s3_cross_account_test

import data.sigcomply.soc2.cc6_6_s3_cross_account

# Test: unrestricted cross-account access should violate
test_unrestricted if {
	result := cc6_6_s3_cross_account.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"bucket_name": "my-bucket",
			"unrestricted_cross_account_access": true,
		},
	}
	count(result) == 1
}

# Test: restricted cross-account access should pass
test_restricted if {
	result := cc6_6_s3_cross_account.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"bucket_name": "my-bucket",
			"unrestricted_cross_account_access": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_s3_cross_account.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds::123:db:mydb",
		"data": {"unrestricted_cross_account_access": true},
	}
	count(result) == 0
}
