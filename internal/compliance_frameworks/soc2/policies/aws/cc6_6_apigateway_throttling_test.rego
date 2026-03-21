package sigcomply.soc2.cc6_6_apigateway_throttling_test

import data.sigcomply.soc2.cc6_6_apigateway_throttling

# Test: stages exist but none have throttling should violate
test_no_throttling if {
	result := cc6_6_apigateway_throttling.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"name": "my-api",
			"stages": [
				{"stage_name": "prod", "throttling_enabled": false},
				{"stage_name": "dev", "throttling_enabled": false},
			],
		},
	}
	count(result) == 1
}

# Test: at least one stage has throttling should pass
test_throttling_enabled if {
	result := cc6_6_apigateway_throttling.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"name": "my-api",
			"stages": [
				{"stage_name": "prod", "throttling_enabled": true},
				{"stage_name": "dev", "throttling_enabled": false},
			],
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_apigateway_throttling.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"stages": [{"stage_name": "prod", "throttling_enabled": false}],
		},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_6_apigateway_throttling.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {},
	}
	count(result) == 0
}
