package sigcomply.soc2.cc6_8_dms_auto_upgrade_test

import data.sigcomply.soc2.cc6_8_dms_auto_upgrade

# Test: DMS instance without auto upgrade should violate
test_no_auto_upgrade if {
	result := cc6_8_dms_auto_upgrade.violations with input as {
		"resource_type": "aws:dms:replication-instance",
		"resource_id": "arn:aws:dms:us-east-1:123:rep:dev-repl",
		"data": {
			"id": "dev-repl",
			"auto_minor_version_upgrade": false,
			"publicly_accessible": false,
			"multi_az": false,
		},
	}
	count(result) == 1
}

# Test: DMS instance with auto upgrade should pass
test_auto_upgrade_enabled if {
	result := cc6_8_dms_auto_upgrade.violations with input as {
		"resource_type": "aws:dms:replication-instance",
		"resource_id": "arn:aws:dms:us-east-1:123:rep:prod-repl",
		"data": {
			"id": "prod-repl",
			"auto_minor_version_upgrade": true,
			"publicly_accessible": false,
			"multi_az": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_8_dms_auto_upgrade.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {"auto_minor_version_upgrade": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_8_dms_auto_upgrade.violations with input as {
		"resource_type": "aws:dms:replication-instance",
		"resource_id": "arn:aws:dms:us-east-1:123:rep:empty",
		"data": {},
	}
	count(result) == 0
}
