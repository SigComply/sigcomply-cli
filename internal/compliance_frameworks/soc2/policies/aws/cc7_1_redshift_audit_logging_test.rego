package sigcomply.soc2.cc7_1_redshift_audit_logging_test

import data.sigcomply.soc2.cc7_1_redshift_audit_logging

test_logging_disabled if {
	result := cc7_1_redshift_audit_logging.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:dev-cluster",
		"data": {"cluster_id": "dev-cluster", "logging_enabled": false},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_1_redshift_audit_logging.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:prod-cluster",
		"data": {"cluster_id": "prod-cluster", "logging_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_redshift_audit_logging.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:test",
		"data": {"logging_enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_1_redshift_audit_logging.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:test",
		"data": {},
	}
	count(result) == 0
}
