package sigcomply.soc2.cc4_1_config_aggregator_test

import data.sigcomply.soc2.cc4_1_config_aggregator

# Test: no aggregator configured should violate
test_not_configured if {
	result := cc4_1_config_aggregator.violations with input as {
		"resource_type": "aws:config:aggregator",
		"resource_id": "aws-account/config-aggregator",
		"data": {
			"configured": false,
		},
	}
	count(result) == 1
}

# Test: aggregator configured should pass
test_configured if {
	result := cc4_1_config_aggregator.violations with input as {
		"resource_type": "aws:config:aggregator",
		"resource_id": "aws-account/config-aggregator",
		"data": {
			"configured": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc4_1_config_aggregator.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"configured": false},
	}
	count(result) == 0
}
