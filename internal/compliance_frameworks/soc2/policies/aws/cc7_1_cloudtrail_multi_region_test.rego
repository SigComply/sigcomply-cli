package sigcomply.soc2.cc7_1_cloudtrail_multi_region_test

import data.sigcomply.soc2.cc7_1_cloudtrail_multi_region

# Test: all non-multi-region trails should violate
test_no_multi_region if {
	result := cc7_1_cloudtrail_multi_region.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-1",
				"data": {"is_multi_region": false},
			},
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-2",
				"data": {"is_multi_region": false},
			},
		],
	}
	count(result) == 1
}

# Test: one multi-region trail should pass
test_has_multi_region if {
	result := cc7_1_cloudtrail_multi_region.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-1",
				"data": {"is_multi_region": true},
			},
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/trail-2",
				"data": {"is_multi_region": false},
			},
		],
	}
	count(result) == 0
}

# Test: no trails should violate
test_no_trails if {
	result := cc7_1_cloudtrail_multi_region.violations with input as {
		"resources": [],
	}
	count(result) == 1
}
