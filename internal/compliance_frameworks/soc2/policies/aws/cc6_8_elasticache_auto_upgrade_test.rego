package sigcomply.soc2.cc6_8_elasticache_auto_upgrade_test

import data.sigcomply.soc2.cc6_8_elasticache_auto_upgrade

# Test: no auto upgrade should violate
test_no_auto_upgrade if {
	result := cc6_8_elasticache_auto_upgrade.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:my-redis",
		"data": {
			"replication_group_id": "my-redis",
			"auto_minor_version_upgrade": false,
		},
	}
	count(result) == 1
}

# Test: auto upgrade enabled should pass
test_auto_upgrade_enabled if {
	result := cc6_8_elasticache_auto_upgrade.violations with input as {
		"resource_type": "aws:elasticache:replication_group",
		"resource_id": "arn:aws:elasticache:us-east-1:123:replicationgroup:my-redis",
		"data": {
			"replication_group_id": "my-redis",
			"auto_minor_version_upgrade": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_8_elasticache_auto_upgrade.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"auto_minor_version_upgrade": false},
	}
	count(result) == 0
}
