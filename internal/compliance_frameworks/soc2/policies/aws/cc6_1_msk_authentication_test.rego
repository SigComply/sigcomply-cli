package sigcomply.soc2.cc6_1_msk_authentication_test

import data.sigcomply.soc2.cc6_1_msk_authentication

test_authentication_disabled if {
	result := cc6_1_msk_authentication.violations with input as {
		"resource_type": "aws:msk:cluster",
		"resource_id": "arn:aws:kafka:us-east-1:123456789012:cluster/prod-kafka/abc123",
		"data": {"cluster_name": "prod-kafka", "authentication_enabled": false},
	}
	count(result) == 1
}

test_authentication_enabled if {
	result := cc6_1_msk_authentication.violations with input as {
		"resource_type": "aws:msk:cluster",
		"resource_id": "arn:aws:kafka:us-east-1:123456789012:cluster/prod-kafka/abc123",
		"data": {"cluster_name": "prod-kafka", "authentication_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_1_msk_authentication.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:db:prod",
		"data": {"authentication_enabled": false},
	}
	count(result) == 0
}
