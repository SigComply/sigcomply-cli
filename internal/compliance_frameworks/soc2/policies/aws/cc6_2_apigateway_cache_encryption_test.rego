package sigcomply.soc2.cc6_2_apigateway_cache_encryption_test

import data.sigcomply.soc2.cc6_2_apigateway_cache_encryption

# Test: stage without cache encryption should violate
test_no_cache_encryption if {
	result := cc6_2_apigateway_cache_encryption.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"name": "my-api",
			"stages": [{"stage_name": "prod", "cache_encryption_enabled": false}],
		},
	}
	count(result) == 1
}

# Test: stage with cache encryption should pass
test_cache_encryption_enabled if {
	result := cc6_2_apigateway_cache_encryption.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"name": "my-api",
			"stages": [{"stage_name": "prod", "cache_encryption_enabled": true}],
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_apigateway_cache_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"stages": [{"stage_name": "prod", "cache_encryption_enabled": false}],
		},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_apigateway_cache_encryption.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {},
	}
	count(result) == 0
}
