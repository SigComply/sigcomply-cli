package sigcomply.soc2.a1_2_neptune_deletion_protection_test

import data.sigcomply.soc2.a1_2_neptune_deletion_protection

# Test: deletion protection disabled should violate
test_deletion_protection_disabled if {
	result := a1_2_neptune_deletion_protection.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"deletion_protection": false,
		},
	}
	count(result) == 1
}

# Test: deletion protection enabled should pass
test_deletion_protection_enabled if {
	result := a1_2_neptune_deletion_protection.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
		"data": {
			"cluster_id": "my-neptune-cluster",
			"arn": "arn:aws:rds:us-east-1:123456789012:cluster:my-neptune-cluster",
			"deletion_protection": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := a1_2_neptune_deletion_protection.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {"deletion_protection": false},
	}
	count(result) == 0
}
