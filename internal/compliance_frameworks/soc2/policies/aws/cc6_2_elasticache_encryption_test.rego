package sigcomply.soc2.cc6_2_elasticache_encryption_test

import data.sigcomply.soc2.cc6_2_elasticache_encryption

test_no_encryption if {
	result := cc6_2_elasticache_encryption.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis",
		"data": {
			"replication_group_id": "prod-redis",
			"at_rest_encryption": false,
		},
	}
	count(result) == 1
}

test_with_encryption if {
	result := cc6_2_elasticache_encryption.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis",
		"data": {
			"replication_group_id": "prod-redis",
			"at_rest_encryption": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_elasticache_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"at_rest_encryption": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_elasticache_encryption.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:test",
		"data": {},
	}
	count(result) == 0
}
