package sigcomply.soc2.cc6_2_dax_encryption_test

import data.sigcomply.soc2.cc6_2_dax_encryption

test_not_encrypted if {
	result := cc6_2_dax_encryption.violations with input as {
		"resource_type": "aws:dax:cluster",
		"resource_id": "arn:aws:dax:us-east-1:123:cache/cluster",
		"data": {"name": "cluster", "sse_enabled": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := cc6_2_dax_encryption.violations with input as {
		"resource_type": "aws:dax:cluster",
		"resource_id": "arn:aws:dax:us-east-1:123:cache/cluster",
		"data": {"name": "cluster", "sse_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_dax_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
