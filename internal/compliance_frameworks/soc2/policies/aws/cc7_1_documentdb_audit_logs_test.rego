package sigcomply.soc2.cc7_1_documentdb_audit_logs_test

import data.sigcomply.soc2.cc7_1_documentdb_audit_logs

test_audit_logs_disabled_violates if {
	result := cc7_1_documentdb_audit_logs.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:dev-docdb",
		"data": {
			"cluster_id": "dev-docdb",
			"audit_logs_enabled": false,
		},
	}
	count(result) == 1
}

test_audit_logs_enabled_passes if {
	result := cc7_1_documentdb_audit_logs.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:prod-docdb",
		"data": {
			"cluster_id": "prod-docdb",
			"audit_logs_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_documentdb_audit_logs.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"cluster_id": "dev-docdb",
			"audit_logs_enabled": false,
		},
	}
	count(result) == 0
}
