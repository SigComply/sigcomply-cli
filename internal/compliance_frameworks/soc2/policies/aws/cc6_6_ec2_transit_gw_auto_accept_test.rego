package sigcomply.soc2.cc6_6_ec2_transit_gw_auto_accept_test

import data.sigcomply.soc2.cc6_6_ec2_transit_gw_auto_accept

test_auto_accept if {
	result := cc6_6_ec2_transit_gw_auto_accept.violations with input as {
		"resource_type": "aws:ec2:transit-gateway",
		"resource_id": "tgw-123",
		"data": {"auto_accept_shared_attachments": true},
	}
	count(result) == 1
}

test_no_auto_accept if {
	result := cc6_6_ec2_transit_gw_auto_accept.violations with input as {
		"resource_type": "aws:ec2:transit-gateway",
		"resource_id": "tgw-123",
		"data": {"auto_accept_shared_attachments": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_ec2_transit_gw_auto_accept.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_ec2_transit_gw_auto_accept.violations with input as {
		"resource_type": "aws:ec2:transit-gateway",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
