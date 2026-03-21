package sigcomply.soc2.cc6_6_documentdb_snapshot_not_public_test

import data.sigcomply.soc2.cc6_6_documentdb_snapshot_not_public

test_public_snapshot_violates if {
	result := cc6_6_documentdb_snapshot_not_public.violations with input as {
		"resource_type": "aws:documentdb:snapshot",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:dev-docdb-snap",
		"data": {
			"snapshot_id": "dev-docdb-snap",
			"is_public": true,
		},
	}
	count(result) == 1
}

test_private_snapshot_passes if {
	result := cc6_6_documentdb_snapshot_not_public.violations with input as {
		"resource_type": "aws:documentdb:snapshot",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:prod-docdb-snap",
		"data": {
			"snapshot_id": "prod-docdb-snap",
			"is_public": false,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_documentdb_snapshot_not_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"snapshot_id": "dev-docdb-snap",
			"is_public": true,
		},
	}
	count(result) == 0
}
