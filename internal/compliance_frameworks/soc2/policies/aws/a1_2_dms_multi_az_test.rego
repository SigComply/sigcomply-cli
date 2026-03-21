package sigcomply.soc2.a1_2_dms_multi_az_test

import data.sigcomply.soc2.a1_2_dms_multi_az

# Test: single-AZ DMS instance should violate
test_single_az if {
	result := a1_2_dms_multi_az.violations with input as {
		"resource_type": "aws:dms:replication-instance",
		"resource_id": "arn:aws:dms:us-east-1:123:rep:dev-repl",
		"data": {
			"id": "dev-repl",
			"multi_az": false,
			"publicly_accessible": false,
			"auto_minor_version_upgrade": true,
		},
	}
	count(result) == 1
}

# Test: multi-AZ DMS instance should pass
test_multi_az if {
	result := a1_2_dms_multi_az.violations with input as {
		"resource_type": "aws:dms:replication-instance",
		"resource_id": "arn:aws:dms:us-east-1:123:rep:prod-repl",
		"data": {
			"id": "prod-repl",
			"multi_az": true,
			"publicly_accessible": false,
			"auto_minor_version_upgrade": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := a1_2_dms_multi_az.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {"multi_az": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := a1_2_dms_multi_az.violations with input as {
		"resource_type": "aws:dms:replication-instance",
		"resource_id": "arn:aws:dms:us-east-1:123:rep:empty",
		"data": {},
	}
	count(result) == 0
}
