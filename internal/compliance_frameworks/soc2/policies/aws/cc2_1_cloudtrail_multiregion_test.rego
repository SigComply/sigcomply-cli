package sigcomply.soc2.cc2_1_cloudtrail_multiregion_test

import data.sigcomply.soc2.cc2_1_cloudtrail_multiregion

test_not_multiregion if {
	result := cc2_1_cloudtrail_multiregion.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/test",
		"data": {"name": "test", "is_multi_region": false},
	}
	count(result) == 1
}

test_multiregion if {
	result := cc2_1_cloudtrail_multiregion.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/test",
		"data": {"name": "test", "is_multi_region": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc2_1_cloudtrail_multiregion.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc2_1_cloudtrail_multiregion.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
