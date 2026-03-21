package sigcomply.soc2.cc6_1_apigateway_authorizer_test

import data.sigcomply.soc2.cc6_1_apigateway_authorizer

# Test: API without authorizer should violate
test_no_authorizer if {
	result := cc6_1_apigateway_authorizer.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"name": "my-api",
			"has_authorizer": false,
		},
	}
	count(result) == 1
}

# Test: API with authorizer should pass
test_has_authorizer if {
	result := cc6_1_apigateway_authorizer.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"name": "my-api",
			"has_authorizer": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_apigateway_authorizer.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_authorizer": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_1_apigateway_authorizer.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {},
	}
	count(result) == 0
}
