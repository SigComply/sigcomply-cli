package sigcomply.soc2.cc6_1_elasticache_auth_test

import data.sigcomply.soc2.cc6_1_elasticache_auth

test_auth_token_disabled if {
	result := cc6_1_elasticache_auth.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis",
		"data": {
			"replication_group_id": "prod-redis",
			"auth_token_enabled": false,
		},
	}
	count(result) == 1
}

test_auth_token_enabled if {
	result := cc6_1_elasticache_auth.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:prod-redis",
		"data": {
			"replication_group_id": "prod-redis",
			"auth_token_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_1_elasticache_auth.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"auth_token_enabled": false},
	}
	count(result) == 0
}
