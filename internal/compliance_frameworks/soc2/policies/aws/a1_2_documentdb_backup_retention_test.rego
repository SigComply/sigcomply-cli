package sigcomply.soc2.a1_2_documentdb_backup_retention_test

import data.sigcomply.soc2.a1_2_documentdb_backup_retention

test_insufficient_backup_retention_violates if {
	result := a1_2_documentdb_backup_retention.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:dev-docdb",
		"data": {
			"cluster_id": "dev-docdb",
			"backup_retention_period": 1,
		},
	}
	count(result) == 1
}

test_sufficient_backup_retention_passes if {
	result := a1_2_documentdb_backup_retention.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:prod-docdb",
		"data": {
			"cluster_id": "prod-docdb",
			"backup_retention_period": 7,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_documentdb_backup_retention.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"cluster_id": "dev-docdb",
			"backup_retention_period": 1,
		},
	}
	count(result) == 0
}
