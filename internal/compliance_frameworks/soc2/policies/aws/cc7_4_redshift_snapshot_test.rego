package sigcomply.soc2.cc7_4_redshift_snapshot_test

import data.sigcomply.soc2.cc7_4_redshift_snapshot

test_no_snapshots if {
	result := cc7_4_redshift_snapshot.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster/mycluster",
		"data": {"cluster_id": "mycluster", "automated_snapshot_retention": 0},
	}
	count(result) == 1
}

test_snapshots_enabled if {
	result := cc7_4_redshift_snapshot.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster/mycluster",
		"data": {"cluster_id": "mycluster", "automated_snapshot_retention": 7},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_4_redshift_snapshot.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_4_redshift_snapshot.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
