package sigcomply.soc2.a1_2_elasticache_multi_az_test

import data.sigcomply.soc2.a1_2_elasticache_multi_az

test_multi_az_disabled if {
	result := a1_2_elasticache_multi_az.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis",
		"data": {
			"replication_group_id": "prod-redis",
			"multi_az_enabled": false,
		},
	}
	count(result) == 1
}

test_multi_az_enabled if {
	result := a1_2_elasticache_multi_az.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis",
		"data": {
			"replication_group_id": "prod-redis",
			"multi_az_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_elasticache_multi_az.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"multi_az_enabled": false},
	}
	count(result) == 0
}
