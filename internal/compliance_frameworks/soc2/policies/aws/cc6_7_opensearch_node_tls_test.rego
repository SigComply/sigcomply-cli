package sigcomply.soc2.cc6_7_opensearch_node_tls_test

import data.sigcomply.soc2.cc6_7_opensearch_node_tls

test_no_node_encryption if {
	result := cc6_7_opensearch_node_tls.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"node_to_node_encryption": false,
		},
	}
	count(result) == 1
}

test_with_node_encryption if {
	result := cc6_7_opensearch_node_tls.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"node_to_node_encryption": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_opensearch_node_tls.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"node_to_node_encryption": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_opensearch_node_tls.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/test",
		"data": {},
	}
	count(result) == 0
}
