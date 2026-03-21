package sigcomply.soc2.cc7_2_cis_organizations_changes_test

import data.sigcomply.soc2.cc7_2_cis_organizations_changes

test_not_configured if {
	result := cc7_2_cis_organizations_changes.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "arn:aws:cloudwatch:us-east-1:123:cis-metric-filter/organizations_changes",
		"data": {"filter_name": "organizations_changes", "configured": false, "region": "us-east-1"},
	}
	count(result) == 1
}

test_configured if {
	result := cc7_2_cis_organizations_changes.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "arn:aws:cloudwatch:us-east-1:123:cis-metric-filter/organizations_changes",
		"data": {"filter_name": "organizations_changes", "configured": true, "region": "us-east-1"},
	}
	count(result) == 0
}

test_wrong_filter_name if {
	result := cc7_2_cis_organizations_changes.violations with input as {
		"resource_type": "aws:cloudwatch:cis-metric-filter",
		"resource_id": "arn:aws:cloudwatch:us-east-1:123:cis-metric-filter/vpc_changes",
		"data": {"filter_name": "vpc_changes", "configured": false, "region": "us-east-1"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_2_cis_organizations_changes.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"filter_name": "organizations_changes", "configured": false},
	}
	count(result) == 0
}
