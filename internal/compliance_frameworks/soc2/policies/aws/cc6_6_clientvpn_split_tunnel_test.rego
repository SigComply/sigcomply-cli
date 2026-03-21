package sigcomply.soc2.cc6_6_clientvpn_split_tunnel_test

import data.sigcomply.soc2.cc6_6_clientvpn_split_tunnel

test_split_tunnel_enabled if {
	result := cc6_6_clientvpn_split_tunnel.violations with input as {
		"resource_type": "aws:ec2:client-vpn-endpoint",
		"resource_id": "arn:aws:ec2::123:client-vpn-endpoint/cvpn-abc",
		"data": {"split_tunnel": true},
	}
	count(result) == 1
}

test_split_tunnel_disabled if {
	result := cc6_6_clientvpn_split_tunnel.violations with input as {
		"resource_type": "aws:ec2:client-vpn-endpoint",
		"resource_id": "arn:aws:ec2::123:client-vpn-endpoint/cvpn-abc",
		"data": {"split_tunnel": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_clientvpn_split_tunnel.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
