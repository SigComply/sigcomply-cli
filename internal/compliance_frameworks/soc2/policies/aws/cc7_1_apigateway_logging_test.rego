package sigcomply.soc2.cc7_1_apigateway_logging_test

import data.sigcomply.soc2.cc7_1_apigateway_logging

test_stage_no_logging if {
	result := cc7_1_apigateway_logging.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"api_id": "abc123",
			"name": "my-api",
			"stages": [
				{"stage_name": "prod", "logging_enabled": false, "access_log_enabled": false},
			],
		},
	}
	count(result) == 1
}

test_stage_with_logging if {
	result := cc7_1_apigateway_logging.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"api_id": "abc123",
			"name": "my-api",
			"stages": [
				{"stage_name": "prod", "logging_enabled": true, "access_log_enabled": true},
			],
		},
	}
	count(result) == 0
}

test_mixed_stages if {
	result := cc7_1_apigateway_logging.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"api_id": "abc123",
			"name": "my-api",
			"stages": [
				{"stage_name": "prod", "logging_enabled": true, "access_log_enabled": true},
				{"stage_name": "dev", "logging_enabled": false, "access_log_enabled": false},
			],
		},
	}
	count(result) == 1
}

test_wrong_resource_type if {
	result := cc7_1_apigateway_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"stages": [{"stage_name": "prod", "logging_enabled": false}]},
	}
	count(result) == 0
}

test_no_stages if {
	result := cc7_1_apigateway_logging.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"api_id": "abc123",
			"name": "my-api",
			"stages": [],
		},
	}
	count(result) == 0
}
