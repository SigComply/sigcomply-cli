package sigcomply.soc2.cc7_2_cis_cmk_disable_deletion_test

import data.sigcomply.soc2.cc7_2_cis_cmk_disable_deletion

# Test: filter not configured should violate
test_not_configured if {
	result := cc7_2_cis_cmk_disable_deletion.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "aws-account/cis-4.7",
		"data": {
			"filter_name": "cmk_disable_deletion",
			"configured": false,
		},
	}
	count(result) == 1
}

# Test: filter configured should pass
test_configured if {
	result := cc7_2_cis_cmk_disable_deletion.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "aws-account/cis-4.7",
		"data": {
			"filter_name": "cmk_disable_deletion",
			"configured": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_2_cis_cmk_disable_deletion.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"filter_name": "cmk_disable_deletion", "configured": false},
	}
	count(result) == 0
}
