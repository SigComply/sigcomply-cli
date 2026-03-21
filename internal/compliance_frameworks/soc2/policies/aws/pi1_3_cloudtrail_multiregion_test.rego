package sigcomply.soc2.pi1_3_cloudtrail_multiregion_test

import data.sigcomply.soc2.pi1_3_cloudtrail_multiregion

test_not_multi_region if {
	result := pi1_3_cloudtrail_multiregion.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/test",
		"data": {"name": "test", "is_multi_region": false},
	}
	count(result) == 1
}

test_multi_region_enabled if {
	result := pi1_3_cloudtrail_multiregion.violations with input as {
		"resource_type": "aws:cloudtrail:trail",
		"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/test",
		"data": {"name": "test", "is_multi_region": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_3_cloudtrail_multiregion.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::test",
		"data": {"is_multi_region": false},
	}
	count(result) == 0
}
