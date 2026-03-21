package sigcomply.soc2.pi1_5_dynamodb_kms_test

import data.sigcomply.soc2.pi1_5_dynamodb_kms

test_default_encryption if {
	result := pi1_5_dynamodb_kms.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/mytable",
		"data": {"name": "mytable", "encryption_type": "DEFAULT"},
	}
	count(result) == 1
}

test_kms_encryption if {
	result := pi1_5_dynamodb_kms.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/mytable",
		"data": {"name": "mytable", "encryption_type": "KMS"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_5_dynamodb_kms.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := pi1_5_dynamodb_kms.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
