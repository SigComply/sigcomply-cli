package sigcomply.soc2.cc7_2_cis_route_table_changes_test

import data.sigcomply.soc2.cc7_2_cis_route_table_changes

# Test: filter not configured should violate
test_not_configured if {
	result := cc7_2_cis_route_table_changes.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "aws-account/cis-4.13",
		"data": {
			"filter_name": "route_table_changes",
			"configured": false,
		},
	}
	count(result) == 1
}

# Test: filter configured should pass
test_configured if {
	result := cc7_2_cis_route_table_changes.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "aws-account/cis-4.13",
		"data": {
			"filter_name": "route_table_changes",
			"configured": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_2_cis_route_table_changes.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"filter_name": "route_table_changes", "configured": false},
	}
	count(result) == 0
}
