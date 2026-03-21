package sigcomply.soc2.cc6_6_dms_not_public_test

import data.sigcomply.soc2.cc6_6_dms_not_public

# Test: public DMS replication instance should violate
test_dms_public if {
	result := cc6_6_dms_not_public.violations with input as {
		"resource_type": "aws:dms:replication-instance",
		"resource_id": "arn:aws:dms:us-east-1:123:rep:dev-repl",
		"data": {
			"id": "dev-repl",
			"publicly_accessible": true,
			"auto_minor_version_upgrade": true,
			"multi_az": false,
		},
	}
	count(result) == 1
}

# Test: private DMS replication instance should pass
test_dms_private if {
	result := cc6_6_dms_not_public.violations with input as {
		"resource_type": "aws:dms:replication-instance",
		"resource_id": "arn:aws:dms:us-east-1:123:rep:prod-repl",
		"data": {
			"id": "prod-repl",
			"publicly_accessible": false,
			"auto_minor_version_upgrade": true,
			"multi_az": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_dms_not_public.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:dev-db",
		"data": {"publicly_accessible": true},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_6_dms_not_public.violations with input as {
		"resource_type": "aws:dms:replication-instance",
		"resource_id": "arn:aws:dms:us-east-1:123:rep:empty",
		"data": {},
	}
	count(result) == 0
}
