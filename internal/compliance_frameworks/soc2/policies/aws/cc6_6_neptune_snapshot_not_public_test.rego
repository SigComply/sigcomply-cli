package sigcomply.soc2.cc6_6_neptune_snapshot_not_public_test

import data.sigcomply.soc2.cc6_6_neptune_snapshot_not_public

# Test: public snapshot should violate
test_public_snapshot if {
	result := cc6_6_neptune_snapshot_not_public.violations with input as {
		"resource_type": "aws:neptune:snapshot",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:my-snapshot",
		"data": {
			"snapshot_id": "my-snapshot",
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:my-snapshot",
			"is_public": true,
		},
	}
	count(result) == 1
}

# Test: private snapshot should pass
test_private_snapshot if {
	result := cc6_6_neptune_snapshot_not_public.violations with input as {
		"resource_type": "aws:neptune:snapshot",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:my-snapshot",
		"data": {
			"snapshot_id": "my-snapshot",
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:my-snapshot",
			"is_public": false,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := cc6_6_neptune_snapshot_not_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"is_public": true},
	}
	count(result) == 0
}
