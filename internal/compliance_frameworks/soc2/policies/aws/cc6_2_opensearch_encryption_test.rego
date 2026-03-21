package sigcomply.soc2.cc6_2_opensearch_encryption_test

import data.sigcomply.soc2.cc6_2_opensearch_encryption

test_unencrypted_opensearch if {
	result := cc6_2_opensearch_encryption.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"encrypted_at_rest": false,
		},
	}
	count(result) == 1
}

test_encrypted_opensearch if {
	result := cc6_2_opensearch_encryption.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"encrypted_at_rest": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_opensearch_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"encrypted_at_rest": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_opensearch_encryption.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/test",
		"data": {},
	}
	count(result) == 0
}
