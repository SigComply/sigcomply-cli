package sigcomply.soc2.cc4_1_config_multi_region_test

import data.sigcomply.soc2.cc4_1_config_multi_region

# Test: all recording should pass
test_all_recording if {
	result := cc4_1_config_multi_region.violations with input as {
		"resources": [
			{
				"resource_type": "aws:config:recorder",
				"resource_id": "arn:aws:config:us-east-1:123:recorder",
				"data": {"enabled": true, "region": "us-east-1"},
			},
			{
				"resource_type": "aws:config:recorder",
				"resource_id": "arn:aws:config:us-west-2:123:recorder",
				"data": {"enabled": true, "region": "us-west-2"},
			},
		],
	}
	count(result) == 0
}

# Test: some not recording should violate
test_some_not_recording if {
	result := cc4_1_config_multi_region.violations with input as {
		"resources": [
			{
				"resource_type": "aws:config:recorder",
				"resource_id": "arn:aws:config:us-east-1:123:recorder",
				"data": {"enabled": true, "region": "us-east-1"},
			},
			{
				"resource_type": "aws:config:recorder",
				"resource_id": "arn:aws:config:us-west-2:123:recorder",
				"data": {"enabled": false, "region": "us-west-2"},
			},
		],
	}
	count(result) == 1
}

# Test: none recording should violate
test_none_recording if {
	result := cc4_1_config_multi_region.violations with input as {
		"resources": [
			{
				"resource_type": "aws:config:recorder",
				"resource_id": "arn:aws:config:us-east-1:123:recorder",
				"data": {"enabled": false, "region": "us-east-1"},
			},
		],
	}
	count(result) == 1
}

# Test: no recorders should violate
test_no_recorders if {
	result := cc4_1_config_multi_region.violations with input as {
		"resources": [],
	}
	count(result) == 1
}
