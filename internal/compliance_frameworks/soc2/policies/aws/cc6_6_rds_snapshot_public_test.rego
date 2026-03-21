package sigcomply.soc2.cc6_6_rds_snapshot_public_test

import data.sigcomply.soc2.cc6_6_rds_snapshot_public

test_public_snapshot if {
	result := cc6_6_rds_snapshot_public.violations with input as {
		"resource_type": "aws:rds:snapshot",
		"resource_id": "arn:aws:rds:us-east-1:123:snapshot:my-snap",
		"data": {
			"snapshot_id": "my-snap",
			"db_instance_id": "prod-db",
			"public": true,
		},
	}
	count(result) == 1
}

test_private_snapshot if {
	result := cc6_6_rds_snapshot_public.violations with input as {
		"resource_type": "aws:rds:snapshot",
		"resource_id": "arn:aws:rds:us-east-1:123:snapshot:my-snap",
		"data": {
			"snapshot_id": "my-snap",
			"db_instance_id": "prod-db",
			"public": false,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_rds_snapshot_public.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:prod-db",
		"data": {"public": true},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_rds_snapshot_public.violations with input as {
		"resource_type": "aws:rds:snapshot",
		"resource_id": "arn:aws:rds:us-east-1:123:snapshot:test",
		"data": {},
	}
	count(result) == 0
}
