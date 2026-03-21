package sigcomply.soc2.a1_2_documentdb_deletion_protection_test

import data.sigcomply.soc2.a1_2_documentdb_deletion_protection

test_deletion_protection_disabled_violates if {
	result := a1_2_documentdb_deletion_protection.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:dev-docdb",
		"data": {
			"cluster_id": "dev-docdb",
			"deletion_protection": false,
		},
	}
	count(result) == 1
}

test_deletion_protection_enabled_passes if {
	result := a1_2_documentdb_deletion_protection.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:prod-docdb",
		"data": {
			"cluster_id": "prod-docdb",
			"deletion_protection": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_documentdb_deletion_protection.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"cluster_id": "dev-docdb",
			"deletion_protection": false,
		},
	}
	count(result) == 0
}
