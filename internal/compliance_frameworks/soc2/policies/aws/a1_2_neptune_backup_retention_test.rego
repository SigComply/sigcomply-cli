package sigcomply.soc2.a1_2_neptune_backup_retention_test

import data.sigcomply.soc2.a1_2_neptune_backup_retention

# Test: insufficient backup retention should violate
test_insufficient_backup_retention if {
	result := a1_2_neptune_backup_retention.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"backup_retention_period": 3,
		},
	}
	count(result) == 1
}

# Test: adequate backup retention should pass
test_adequate_backup_retention if {
	result := a1_2_neptune_backup_retention.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"backup_retention_period": 7,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := a1_2_neptune_backup_retention.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"backup_retention_period": 1},
	}
	count(result) == 0
}
