package sigcomply.soc2.cc7_1_opensearch_slow_logs_test

import data.sigcomply.soc2.cc7_1_opensearch_slow_logs

test_slow_logs_disabled if {
	result := cc7_1_opensearch_slow_logs.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"slow_logs_enabled": false,
		},
	}
	count(result) == 1
}

test_slow_logs_enabled if {
	result := cc7_1_opensearch_slow_logs.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"slow_logs_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_opensearch_slow_logs.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"slow_logs_enabled": false},
	}
	count(result) == 0
}
