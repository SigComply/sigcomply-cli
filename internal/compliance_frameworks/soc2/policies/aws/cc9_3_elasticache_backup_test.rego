package sigcomply.soc2.cc9_3_elasticache_backup_test

import data.sigcomply.soc2.cc9_3_elasticache_backup

test_backup_disabled if {
	result := cc9_3_elasticache_backup.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis",
		"data": {
			"replication_group_id": "prod-redis",
			"snapshot_retention_limit": 0,
		},
	}
	count(result) == 1
}

test_backup_enabled if {
	result := cc9_3_elasticache_backup.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis",
		"data": {
			"replication_group_id": "prod-redis",
			"snapshot_retention_limit": 7,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc9_3_elasticache_backup.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"snapshot_retention_limit": 0},
	}
	count(result) == 0
}
