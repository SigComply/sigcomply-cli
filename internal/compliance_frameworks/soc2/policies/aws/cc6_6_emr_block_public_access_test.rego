package sigcomply.soc2.cc6_6_emr_block_public_access_test

import data.sigcomply.soc2.cc6_6_emr_block_public_access

# Test: block public access disabled should violate
test_block_public_access_disabled if {
	result := cc6_6_emr_block_public_access.violations with input as {
		"resource_type": "aws:emr:block-public-access",
		"resource_id": "arn:aws:emr:us-east-1:123456789012:block-public-access",
		"data": {
			"region": "us-east-1",
			"block_public_access": false,
		},
	}
	count(result) == 1
}

# Test: block public access enabled should pass
test_block_public_access_enabled if {
	result := cc6_6_emr_block_public_access.violations with input as {
		"resource_type": "aws:emr:block-public-access",
		"resource_id": "arn:aws:emr:us-east-1:123456789012:block-public-access",
		"data": {
			"region": "us-east-1",
			"block_public_access": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_emr_block_public_access.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"block_public_access": false},
	}
	count(result) == 0
}
