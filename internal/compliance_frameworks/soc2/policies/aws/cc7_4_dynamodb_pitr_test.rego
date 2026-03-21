package sigcomply.soc2.cc7_4_dynamodb_pitr_test

import data.sigcomply.soc2.cc7_4_dynamodb_pitr

test_no_pitr if {
	result := cc7_4_dynamodb_pitr.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/mytable",
		"data": {"name": "mytable", "pitr_enabled": false},
	}
	count(result) == 1
}

test_pitr_enabled if {
	result := cc7_4_dynamodb_pitr.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/mytable",
		"data": {"name": "mytable", "pitr_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_4_dynamodb_pitr.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_4_dynamodb_pitr.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
