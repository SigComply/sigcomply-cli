package sigcomply.soc2.cc6_6_opensearch_enforce_https_test

import data.sigcomply.soc2.cc6_6_opensearch_enforce_https

test_no_https if {
	result := cc6_6_opensearch_enforce_https.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"enforce_https": false,
		},
	}
	count(result) == 1
}

test_with_https if {
	result := cc6_6_opensearch_enforce_https.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"enforce_https": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_opensearch_enforce_https.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enforce_https": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_opensearch_enforce_https.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/test",
		"data": {},
	}
	count(result) == 0
}
