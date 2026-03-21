package sigcomply.soc2.a1_2_redshift_automated_snapshots_test

import data.sigcomply.soc2.a1_2_redshift_automated_snapshots

test_no_snapshots if {
	result := a1_2_redshift_automated_snapshots.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:namespace:prod",
		"data": {"cluster_id": "prod", "automated_snapshot_retention": 0},
	}
	count(result) == 1
}

test_snapshots_enabled if {
	result := a1_2_redshift_automated_snapshots.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:namespace:prod",
		"data": {"cluster_id": "prod", "automated_snapshot_retention": 7},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_redshift_automated_snapshots.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod",
		"data": {"automated_snapshot_retention": 0},
	}
	count(result) == 0
}
