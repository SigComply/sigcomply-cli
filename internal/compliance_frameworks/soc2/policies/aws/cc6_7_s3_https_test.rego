package sigcomply.soc2.cc6_7_s3_https_test

import data.sigcomply.soc2.cc6_7_s3_https

# Test: bucket without SSL enforcement should violate
test_no_ssl_enforcement if {
	result := cc6_7_s3_https.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"has_ssl_enforcement": false,
			"bucket_policy_exists": false,
		},
	}
	count(result) == 1
}

# Test: bucket with SSL enforcement should pass
test_ssl_enforced if {
	result := cc6_7_s3_https.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::secure-bucket",
		"data": {
			"name": "secure-bucket",
			"has_ssl_enforcement": true,
			"bucket_policy_exists": true,
		},
	}
	count(result) == 0
}

# Test: bucket with policy but no SSL enforcement should violate
test_policy_without_ssl if {
	result := cc6_7_s3_https.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::partial-bucket",
		"data": {
			"name": "partial-bucket",
			"has_ssl_enforcement": false,
			"bucket_policy_exists": true,
		},
	}
	count(result) == 1
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_7_s3_https.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:db",
		"data": {"has_ssl_enforcement": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_7_s3_https.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::empty",
		"data": {},
	}
	count(result) == 0
}
