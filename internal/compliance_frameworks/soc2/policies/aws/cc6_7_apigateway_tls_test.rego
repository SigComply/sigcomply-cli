package sigcomply.soc2.cc6_7_apigateway_tls_test

import data.sigcomply.soc2.cc6_7_apigateway_tls

test_tls_1_0_enabled if {
	result := cc6_7_apigateway_tls.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"api_id": "abc123",
			"name": "my-api",
			"tls_1_0_enabled": true,
		},
	}
	count(result) == 1
}

test_tls_1_0_disabled if {
	result := cc6_7_apigateway_tls.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"api_id": "abc123",
			"name": "my-api",
			"tls_1_0_enabled": false,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_apigateway_tls.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"tls_1_0_enabled": true},
	}
	count(result) == 0
}
