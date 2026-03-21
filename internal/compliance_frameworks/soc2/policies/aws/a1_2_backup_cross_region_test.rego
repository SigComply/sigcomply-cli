package sigcomply.soc2.a1_2_backup_cross_region_test

import data.sigcomply.soc2.a1_2_backup_cross_region

test_no_cross_region if {
	result := a1_2_backup_cross_region.violations with input as {
		"resource_type": "aws:backup:plan",
		"resource_id": "arn:aws:backup:us-east-1:123:backup-plan:plan-1",
		"data": {
			"plan_id": "plan-1",
			"plan_name": "daily-backup",
			"has_cross_region_copy": false,
		},
	}
	count(result) == 1
}

test_with_cross_region if {
	result := a1_2_backup_cross_region.violations with input as {
		"resource_type": "aws:backup:plan",
		"resource_id": "arn:aws:backup:us-east-1:123:backup-plan:plan-1",
		"data": {
			"plan_id": "plan-1",
			"plan_name": "daily-backup",
			"has_cross_region_copy": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_backup_cross_region.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_cross_region_copy": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := a1_2_backup_cross_region.violations with input as {
		"resource_type": "aws:backup:plan",
		"resource_id": "arn:aws:backup:us-east-1:123:backup-plan:test",
		"data": {},
	}
	count(result) == 0
}
