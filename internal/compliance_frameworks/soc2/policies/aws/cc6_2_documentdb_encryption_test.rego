package sigcomply.soc2.cc6_2_documentdb_encryption_test

import data.sigcomply.soc2.cc6_2_documentdb_encryption

test_unencrypted_cluster_violates if {
	result := cc6_2_documentdb_encryption.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:dev-docdb",
		"data": {
			"cluster_id": "dev-docdb",
			"storage_encrypted": false,
		},
	}
	count(result) == 1
}

test_encrypted_cluster_passes if {
	result := cc6_2_documentdb_encryption.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:prod-docdb",
		"data": {
			"cluster_id": "prod-docdb",
			"storage_encrypted": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_documentdb_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"cluster_id": "dev-docdb",
			"storage_encrypted": false,
		},
	}
	count(result) == 0
}
