package sigcomply.soc2.cc7_1_msk_logging_test

import data.sigcomply.soc2.cc7_1_msk_logging

test_logging_disabled if {
	result := cc7_1_msk_logging.violations with input as {
		"resource_type": "aws:msk:cluster",
		"resource_id": "arn:aws:kafka:us-east-1:123456789012:cluster/prod-kafka/abc123",
		"data": {"cluster_name": "prod-kafka", "logging_enabled": false},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_1_msk_logging.violations with input as {
		"resource_type": "aws:msk:cluster",
		"resource_id": "arn:aws:kafka:us-east-1:123456789012:cluster/prod-kafka/abc123",
		"data": {"cluster_name": "prod-kafka", "logging_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_msk_logging.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:db:prod",
		"data": {"logging_enabled": false},
	}
	count(result) == 0
}
