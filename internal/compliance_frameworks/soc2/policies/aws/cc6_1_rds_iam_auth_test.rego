package sigcomply.soc2.cc6_1_rds_iam_auth_test

import data.sigcomply.soc2.cc6_1_rds_iam_auth

# Test: IAM auth disabled should violate
test_iam_auth_disabled if {
	result := cc6_1_rds_iam_auth.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"engine": "mysql",
			"iam_database_authentication_enabled": false,
		},
	}
	count(result) == 1
}

# Test: IAM auth enabled should pass
test_iam_auth_enabled if {
	result := cc6_1_rds_iam_auth.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {
			"db_instance_id": "mydb",
			"engine": "mysql",
			"iam_database_authentication_enabled": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_rds_iam_auth.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"iam_database_authentication_enabled": false},
	}
	count(result) == 0
}
