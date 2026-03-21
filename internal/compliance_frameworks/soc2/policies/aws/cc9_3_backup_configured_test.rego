package sigcomply.soc2.cc9_3_backup_configured_test

import data.sigcomply.soc2.cc9_3_backup_configured

# Test: has backup plans should pass
test_has_plans if {
	result := cc9_3_backup_configured.violations with input as {
		"resource_type": "aws:backup:status",
		"resource_id": "arn:aws:backup:us-east-1:123:status",
		"data": {
			"has_backup_plans": true,
			"plan_count": 2,
			"region": "us-east-1",
		},
	}
	count(result) == 0
}

# Test: no backup plans should violate
test_no_plans if {
	result := cc9_3_backup_configured.violations with input as {
		"resource_type": "aws:backup:status",
		"resource_id": "arn:aws:backup:us-east-1:123:status",
		"data": {
			"has_backup_plans": false,
			"plan_count": 0,
			"region": "us-east-1",
		},
	}
	count(result) == 1
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc9_3_backup_configured.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_backup_plans": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc9_3_backup_configured.violations with input as {
		"resource_type": "aws:backup:status",
		"resource_id": "arn:aws:backup:us-east-1:123:status",
		"data": {},
	}
	count(result) == 0
}
