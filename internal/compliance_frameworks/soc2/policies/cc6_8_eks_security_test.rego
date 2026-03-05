package sigcomply.soc2.cc6_8_eks_security_test

import data.sigcomply.soc2.cc6_8_eks_security

test_all_violations if {
	result := cc6_8_eks_security.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/dev",
		"data": {"name": "dev", "endpoint_public_access": true, "logging_enabled": false, "secrets_encryption": false},
	}
	count(result) == 3
}

# Individual violation: only public endpoint
test_only_public_endpoint if {
	result := cc6_8_eks_security.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/dev",
		"data": {"name": "dev", "endpoint_public_access": true, "logging_enabled": true, "secrets_encryption": true},
	}
	count(result) == 1
}

# Individual violation: only logging disabled
test_only_logging_disabled if {
	result := cc6_8_eks_security.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/dev",
		"data": {"name": "dev", "endpoint_public_access": false, "logging_enabled": false, "secrets_encryption": true},
	}
	count(result) == 1
}

# Individual violation: only secrets encryption disabled
test_only_secrets_encryption_disabled if {
	result := cc6_8_eks_security.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/dev",
		"data": {"name": "dev", "endpoint_public_access": false, "logging_enabled": true, "secrets_encryption": false},
	}
	count(result) == 1
}

# Partial violations: two out of three
test_two_violations if {
	result := cc6_8_eks_security.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/dev",
		"data": {"name": "dev", "endpoint_public_access": true, "logging_enabled": false, "secrets_encryption": true},
	}
	count(result) == 2
}

test_secure_cluster if {
	result := cc6_8_eks_security.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/prod",
		"data": {"name": "prod", "endpoint_public_access": false, "logging_enabled": true, "secrets_encryption": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_eks_security.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"endpoint_public_access": true},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_8_eks_security.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/test",
		"data": {},
	}
	count(result) == 0
}
