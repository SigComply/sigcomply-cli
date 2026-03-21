package sigcomply.soc2.cc6_2_neptune_encryption_test

import data.sigcomply.soc2.cc6_2_neptune_encryption

# Test: unencrypted cluster should violate
test_unencrypted_cluster if {
	result := cc6_2_neptune_encryption.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"storage_encrypted": false,
		},
	}
	count(result) == 1
}

# Test: encrypted cluster should pass
test_encrypted_cluster if {
	result := cc6_2_neptune_encryption.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"storage_encrypted": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := cc6_2_neptune_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"storage_encrypted": false},
	}
	count(result) == 0
}
