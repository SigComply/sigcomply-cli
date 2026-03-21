package sigcomply.soc2.cc7_1_route53_query_logging_test

import data.sigcomply.soc2.cc7_1_route53_query_logging

# Test: public zone without query logging should violate
test_public_zone_no_logging if {
	result := cc7_1_route53_query_logging.violations with input as {
		"resource_type": "aws:route53:hosted-zone",
		"resource_id": "arn:aws:route53:::hostedzone/Z1234567890",
		"data": {
			"zone_name": "example.com.",
			"zone_id": "Z1234567890",
			"is_private": false,
			"query_logging": false,
		},
	}
	count(result) == 1
}

# Test: public zone with query logging should pass
test_public_zone_with_logging if {
	result := cc7_1_route53_query_logging.violations with input as {
		"resource_type": "aws:route53:hosted-zone",
		"resource_id": "arn:aws:route53:::hostedzone/Z1234567890",
		"data": {
			"zone_name": "example.com.",
			"zone_id": "Z1234567890",
			"is_private": false,
			"query_logging": true,
		},
	}
	count(result) == 0
}

# Test: private zone without query logging should pass (only public zones are checked)
test_private_zone_no_logging if {
	result := cc7_1_route53_query_logging.violations with input as {
		"resource_type": "aws:route53:hosted-zone",
		"resource_id": "arn:aws:route53:::hostedzone/Z9876543210",
		"data": {
			"zone_name": "internal.example.com.",
			"zone_id": "Z9876543210",
			"is_private": true,
			"query_logging": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_1_route53_query_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"is_private": false,
			"query_logging": false,
		},
	}
	count(result) == 0
}
