package sigcomply.soc2.cc4_2_guardduty_multi_region_test

import data.sigcomply.soc2.cc4_2_guardduty_multi_region

# Test: all enabled should pass
test_all_enabled if {
	result := cc4_2_guardduty_multi_region.violations with input as {
		"resources": [
			{
				"resource_type": "aws:guardduty:detector",
				"resource_id": "arn:aws:guardduty:us-east-1:123:detector",
				"data": {"enabled": true, "region": "us-east-1"},
			},
			{
				"resource_type": "aws:guardduty:detector",
				"resource_id": "arn:aws:guardduty:us-west-2:123:detector",
				"data": {"enabled": true, "region": "us-west-2"},
			},
		],
	}
	count(result) == 0
}

# Test: some disabled should violate with region list
test_some_disabled if {
	result := cc4_2_guardduty_multi_region.violations with input as {
		"resources": [
			{
				"resource_type": "aws:guardduty:detector",
				"resource_id": "arn:aws:guardduty:us-east-1:123:detector",
				"data": {"enabled": true, "region": "us-east-1"},
			},
			{
				"resource_type": "aws:guardduty:detector",
				"resource_id": "arn:aws:guardduty:us-west-2:123:detector",
				"data": {"enabled": false, "region": "us-west-2"},
			},
		],
	}
	count(result) == 1
}

# Test: all disabled should violate
test_all_disabled if {
	result := cc4_2_guardduty_multi_region.violations with input as {
		"resources": [
			{
				"resource_type": "aws:guardduty:detector",
				"resource_id": "arn:aws:guardduty:us-east-1:123:detector",
				"data": {"enabled": false, "region": "us-east-1"},
			},
			{
				"resource_type": "aws:guardduty:detector",
				"resource_id": "arn:aws:guardduty:us-west-2:123:detector",
				"data": {"enabled": false, "region": "us-west-2"},
			},
		],
	}
	count(result) == 1
}

# Test: no resources should pass (no violation without data)
test_no_resources if {
	result := cc4_2_guardduty_multi_region.violations with input as {
		"resources": [],
	}
	count(result) == 0
}
