package sigcomply.soc2.cc6_6_opensearch_vpc_test

import data.sigcomply.soc2.cc6_6_opensearch_vpc

test_no_vpc if {
	result := cc6_6_opensearch_vpc.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"vpc_configured": false,
		},
	}
	count(result) == 1
}

test_with_vpc if {
	result := cc6_6_opensearch_vpc.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"vpc_configured": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_opensearch_vpc.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"vpc_configured": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_opensearch_vpc.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/test",
		"data": {},
	}
	count(result) == 0
}
