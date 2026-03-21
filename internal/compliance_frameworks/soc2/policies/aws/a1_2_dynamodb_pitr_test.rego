package sigcomply.soc2.a1_2_dynamodb_pitr_test

import data.sigcomply.soc2.a1_2_dynamodb_pitr

test_pitr_disabled if {
	result := a1_2_dynamodb_pitr.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/users",
		"data": {"name": "users", "pitr_enabled": false},
	}
	count(result) == 1
}

test_pitr_enabled if {
	result := a1_2_dynamodb_pitr.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/users",
		"data": {"name": "users", "pitr_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_dynamodb_pitr.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"pitr_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := a1_2_dynamodb_pitr.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/users",
		"data": {},
	}
	count(result) == 0
}
