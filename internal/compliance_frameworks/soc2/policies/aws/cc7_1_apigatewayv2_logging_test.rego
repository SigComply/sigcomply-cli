package sigcomply.soc2.cc7_1_apigatewayv2_logging_test

import data.sigcomply.soc2.cc7_1_apigatewayv2_logging

test_no_logging if {
	result := cc7_1_apigatewayv2_logging.violations with input as {
		"resource_type": "aws:apigateway:v2-api",
		"resource_id": "abc123",
		"data": {"name": "my-http-api", "access_logging_enabled": false},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_1_apigatewayv2_logging.violations with input as {
		"resource_type": "aws:apigateway:v2-api",
		"resource_id": "abc123",
		"data": {"name": "my-http-api", "access_logging_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_apigatewayv2_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_apigatewayv2_logging.violations with input as {
		"resource_type": "aws:apigateway:v2-api",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
