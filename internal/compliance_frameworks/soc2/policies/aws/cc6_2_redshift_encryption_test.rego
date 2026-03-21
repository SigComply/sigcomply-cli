package sigcomply.soc2.cc6_2_redshift_encryption_test

import data.sigcomply.soc2.cc6_2_redshift_encryption

test_unencrypted_cluster if {
	result := cc6_2_redshift_encryption.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:dev-cluster",
		"data": {"cluster_id": "dev-cluster", "encrypted": false},
	}
	count(result) == 1
}

test_encrypted_cluster if {
	result := cc6_2_redshift_encryption.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:prod-cluster",
		"data": {"cluster_id": "prod-cluster", "encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_redshift_encryption.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:test",
		"data": {"encrypted": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_redshift_encryption.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:test",
		"data": {},
	}
	count(result) == 0
}
