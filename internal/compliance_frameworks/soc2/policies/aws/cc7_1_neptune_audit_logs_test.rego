package sigcomply.soc2.cc7_1_neptune_audit_logs_test

import data.sigcomply.soc2.cc7_1_neptune_audit_logs

# Test: audit logs disabled should violate
test_audit_logs_disabled if {
	result := cc7_1_neptune_audit_logs.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"audit_logs_enabled": false,
		},
	}
	count(result) == 1
}

# Test: audit logs enabled should pass
test_audit_logs_enabled if {
	result := cc7_1_neptune_audit_logs.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"audit_logs_enabled": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := cc7_1_neptune_audit_logs.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"audit_logs_enabled": false},
	}
	count(result) == 0
}
