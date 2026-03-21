package sigcomply.soc2.cc6_7_documentdb_tls_test

import data.sigcomply.soc2.cc6_7_documentdb_tls

test_tls_disabled_violates if {
	result := cc6_7_documentdb_tls.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:dev-docdb",
		"data": {
			"cluster_id": "dev-docdb",
			"tls_enabled": false,
		},
	}
	count(result) == 1
}

test_tls_enabled_passes if {
	result := cc6_7_documentdb_tls.violations with input as {
		"resource_type": "aws:documentdb:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:prod-docdb",
		"data": {
			"cluster_id": "prod-docdb",
			"tls_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_documentdb_tls.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"cluster_id": "dev-docdb",
			"tls_enabled": false,
		},
	}
	count(result) == 0
}
