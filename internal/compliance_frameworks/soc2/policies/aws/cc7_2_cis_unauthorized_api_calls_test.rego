package sigcomply.soc2.cc7_2_cis_unauthorized_api_calls_test

import data.sigcomply.soc2.cc7_2_cis_unauthorized_api_calls

# Test: filter not configured should violate
test_not_configured if {
	result := cc7_2_cis_unauthorized_api_calls.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "aws-account/cis-4.1",
		"data": {
			"filter_name": "unauthorized_api_calls",
			"configured": false,
		},
	}
	count(result) == 1
}

# Test: filter configured should pass
test_configured if {
	result := cc7_2_cis_unauthorized_api_calls.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "aws-account/cis-4.1",
		"data": {
			"filter_name": "unauthorized_api_calls",
			"configured": true,
		},
	}
	count(result) == 0
}

# Test: different filter name should not trigger
test_different_filter if {
	result := cc7_2_cis_unauthorized_api_calls.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "aws-account/cis-other",
		"data": {
			"filter_name": "other_filter",
			"configured": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_2_cis_unauthorized_api_calls.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"filter_name": "unauthorized_api_calls", "configured": false},
	}
	count(result) == 0
}
