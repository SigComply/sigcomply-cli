package sigcomply.soc2.cc7_1_opensearch_audit_logging_test

import data.sigcomply.soc2.cc7_1_opensearch_audit_logging

test_audit_logging_disabled if {
	result := cc7_1_opensearch_audit_logging.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"audit_logging_enabled": false,
		},
	}
	count(result) == 1
}

test_audit_logging_enabled if {
	result := cc7_1_opensearch_audit_logging.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"audit_logging_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_opensearch_audit_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"audit_logging_enabled": false},
	}
	count(result) == 0
}
