package sigcomply.soc2.cc6_2_eks_secrets_encryption_test

import data.sigcomply.soc2.cc6_2_eks_secrets_encryption

# Test: cluster without secrets encryption should violate
test_no_secrets_encryption if {
	result := cc6_2_eks_secrets_encryption.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/my-cluster",
		"data": {
			"name": "my-cluster",
			"secrets_encryption": false,
		},
	}
	count(result) == 1
}

# Test: cluster with secrets encryption should pass
test_secrets_encryption_enabled if {
	result := cc6_2_eks_secrets_encryption.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/my-cluster",
		"data": {
			"name": "my-cluster",
			"secrets_encryption": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_eks_secrets_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"secrets_encryption": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_eks_secrets_encryption.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/test",
		"data": {},
	}
	count(result) == 0
}
