package sigcomply.soc2.cc6_7_emr_encryption_in_transit_test

import data.sigcomply.soc2.cc6_7_emr_encryption_in_transit

# Test: encryption in transit disabled should violate
test_encryption_in_transit_disabled if {
	result := cc6_7_emr_encryption_in_transit.violations with input as {
		"resource_type": "aws:emr:cluster",
		"resource_id": "arn:aws:emr:us-east-1:123456789012:cluster/j-1234567890ABC",
		"data": {
			"name": "dev-cluster",
			"id": "j-1234567890ABC",
			"encryption_in_transit": false,
		},
	}
	count(result) == 1
}

# Test: encryption in transit enabled should pass
test_encryption_in_transit_enabled if {
	result := cc6_7_emr_encryption_in_transit.violations with input as {
		"resource_type": "aws:emr:cluster",
		"resource_id": "arn:aws:emr:us-east-1:123456789012:cluster/j-ABCDEF1234567",
		"data": {
			"name": "prod-cluster",
			"id": "j-ABCDEF1234567",
			"encryption_in_transit": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_7_emr_encryption_in_transit.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"encryption_in_transit": false},
	}
	count(result) == 0
}
