package sigcomply.soc2.cc6_1_opensearch_fine_grained_access_test

import data.sigcomply.soc2.cc6_1_opensearch_fine_grained_access

test_fine_grained_access_disabled if {
	result := cc6_1_opensearch_fine_grained_access.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"fine_grained_access_enabled": false,
		},
	}
	count(result) == 1
}

test_fine_grained_access_enabled if {
	result := cc6_1_opensearch_fine_grained_access.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"fine_grained_access_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_1_opensearch_fine_grained_access.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"fine_grained_access_enabled": false},
	}
	count(result) == 0
}
