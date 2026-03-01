package sigcomply.soc2.cc8_1_config_test

import data.sigcomply.soc2.cc8_1_config

# Test: Config not enabled should violate
test_config_disabled if {
	result := cc8_1_config.violations with input as {
		"resource_type": "aws:config:recorder",
		"resource_id": "arn:aws:config:us-east-1:123:recorder",
		"data": {
			"enabled": false,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Test: Config enabled should pass
test_config_enabled if {
	result := cc8_1_config.violations with input as {
		"resource_type": "aws:config:recorder",
		"resource_id": "arn:aws:config:us-east-1:123:recorder",
		"data": {
			"enabled": true,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc8_1_config.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {"enabled": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc8_1_config.violations with input as {
		"resource_type": "aws:config:recorder",
		"resource_id": "arn:aws:config:us-east-1:123:recorder",
		"data": {},
	}
	count(result) == 0
}
