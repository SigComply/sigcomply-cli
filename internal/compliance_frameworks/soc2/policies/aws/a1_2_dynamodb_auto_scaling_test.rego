package sigcomply.soc2.a1_2_dynamodb_auto_scaling_test

import data.sigcomply.soc2.a1_2_dynamodb_auto_scaling

test_provisioned_billing if {
	result := a1_2_dynamodb_auto_scaling.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/users",
		"data": {"name": "users", "billing_mode": "PROVISIONED"},
	}
	count(result) == 1
}

test_on_demand_billing if {
	result := a1_2_dynamodb_auto_scaling.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/users",
		"data": {"name": "users", "billing_mode": "PAY_PER_REQUEST"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_dynamodb_auto_scaling.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"billing_mode": "PROVISIONED"},
	}
	count(result) == 0
}

test_empty_data if {
	result := a1_2_dynamodb_auto_scaling.violations with input as {
		"resource_type": "aws:dynamodb:table",
		"resource_id": "arn:aws:dynamodb:us-east-1:123:table/users",
		"data": {},
	}
	count(result) == 0
}
