package sigcomply.soc2.cc6_6_msk_no_public_access_test

import data.sigcomply.soc2.cc6_6_msk_no_public_access

test_public_access_enabled if {
	result := cc6_6_msk_no_public_access.violations with input as {
		"resource_type": "aws:msk:cluster",
		"resource_id": "arn:aws:kafka:us-east-1:123456789012:cluster/prod-kafka/abc123",
		"data": {"cluster_name": "prod-kafka", "public_access": true},
	}
	count(result) == 1
}

test_public_access_disabled if {
	result := cc6_6_msk_no_public_access.violations with input as {
		"resource_type": "aws:msk:cluster",
		"resource_id": "arn:aws:kafka:us-east-1:123456789012:cluster/prod-kafka/abc123",
		"data": {"cluster_name": "prod-kafka", "public_access": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_msk_no_public_access.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:db:prod",
		"data": {"public_access": true},
	}
	count(result) == 0
}
