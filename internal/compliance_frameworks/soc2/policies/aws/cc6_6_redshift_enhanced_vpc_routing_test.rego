package sigcomply.soc2.cc6_6_redshift_enhanced_vpc_routing_test

import data.sigcomply.soc2.cc6_6_redshift_enhanced_vpc_routing

# Test: no enhanced VPC routing should violate
test_no_enhanced_vpc_routing if {
	result := cc6_6_redshift_enhanced_vpc_routing.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:my-cluster",
		"data": {
			"cluster_id": "my-cluster",
			"enhanced_vpc_routing": false,
		},
	}
	count(result) == 1
}

# Test: enhanced VPC routing enabled should pass
test_enhanced_vpc_routing_enabled if {
	result := cc6_6_redshift_enhanced_vpc_routing.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:my-cluster",
		"data": {
			"cluster_id": "my-cluster",
			"enhanced_vpc_routing": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_redshift_enhanced_vpc_routing.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enhanced_vpc_routing": false},
	}
	count(result) == 0
}
