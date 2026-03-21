package sigcomply.soc2.cc6_7_msk_encryption_in_transit_test

import data.sigcomply.soc2.cc6_7_msk_encryption_in_transit

test_no_encryption_in_transit if {
	result := cc6_7_msk_encryption_in_transit.violations with input as {
		"resource_type": "aws:msk:cluster",
		"resource_id": "arn:aws:kafka:us-east-1:123456789012:cluster/prod-kafka/abc123",
		"data": {"cluster_name": "prod-kafka", "encryption_in_transit": false},
	}
	count(result) == 1
}

test_encryption_in_transit_enabled if {
	result := cc6_7_msk_encryption_in_transit.violations with input as {
		"resource_type": "aws:msk:cluster",
		"resource_id": "arn:aws:kafka:us-east-1:123456789012:cluster/prod-kafka/abc123",
		"data": {"cluster_name": "prod-kafka", "encryption_in_transit": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_msk_encryption_in_transit.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123456789012:db:prod",
		"data": {"encryption_in_transit": false},
	}
	count(result) == 0
}
