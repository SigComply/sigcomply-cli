package sigcomply.soc2.cc6_2_s3_public_test

import data.sigcomply.soc2.cc6_2_s3_public

# Test: public access not blocked should violate
test_public_access_not_blocked if {
	result := cc6_2_s3_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"public_access_blocked": false,
		},
	}
	count(result) == 1
}

# Test: public access blocked should pass
test_public_access_blocked if {
	result := cc6_2_s3_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"public_access_blocked": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_s3_public.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:db",
		"data": {"public_access_blocked": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_s3_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::empty",
		"data": {},
	}
	count(result) == 0
}
