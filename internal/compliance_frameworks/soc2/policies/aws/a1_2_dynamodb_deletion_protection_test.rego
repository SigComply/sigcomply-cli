package sigcomply.soc2.a1_2_dynamodb_deletion_protection_test

import data.sigcomply.soc2.a1_2_dynamodb_deletion_protection

# Test: no deletion protection should violate
test_no_deletion_protection if {
	result := a1_2_dynamodb_deletion_protection.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/my-table",
		"data": {
			"name": "my-table",
			"deletion_protection": false,
		},
	}
	count(result) == 1
}

# Test: deletion protection enabled should pass
test_deletion_protection_enabled if {
	result := a1_2_dynamodb_deletion_protection.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/my-table",
		"data": {
			"name": "my-table",
			"deletion_protection": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := a1_2_dynamodb_deletion_protection.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"deletion_protection": false},
	}
	count(result) == 0
}
