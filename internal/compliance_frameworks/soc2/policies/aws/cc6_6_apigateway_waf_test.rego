package sigcomply.soc2.cc6_6_apigateway_waf_test

import data.sigcomply.soc2.cc6_6_apigateway_waf

test_waf_not_associated if {
	result := cc6_6_apigateway_waf.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"api_id": "abc123",
			"name": "my-api",
			"waf_enabled": false,
		},
	}
	count(result) == 1
}

test_waf_associated if {
	result := cc6_6_apigateway_waf.violations with input as {
		"resource_type": "aws:apigateway:rest_api",
		"resource_id": "arn:aws:apigateway::123::/restapis/abc123",
		"data": {
			"api_id": "abc123",
			"name": "my-api",
			"waf_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_apigateway_waf.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"waf_enabled": false},
	}
	count(result) == 0
}
