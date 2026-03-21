package sigcomply.soc2.cc6_6_networkfirewall_policy_test

import data.sigcomply.soc2.cc6_6_networkfirewall_policy

test_no_firewall_policy if {
	result := cc6_6_networkfirewall_policy.violations with input as {
		"resource_type": "aws:networkfirewall:firewall",
		"resource_id": "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall",
		"data": {
			"firewall_name": "my-firewall",
			"arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall",
			"logging_enabled": true,
			"deletion_protection": true,
			"has_firewall_policy": false,
		},
	}
	count(result) == 1
}

test_firewall_policy_attached if {
	result := cc6_6_networkfirewall_policy.violations with input as {
		"resource_type": "aws:networkfirewall:firewall",
		"resource_id": "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall",
		"data": {
			"firewall_name": "my-firewall",
			"arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall",
			"logging_enabled": true,
			"deletion_protection": true,
			"has_firewall_policy": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_networkfirewall_policy.violations with input as {
		"resource_type": "aws:wafv2:status",
		"resource_id": "arn:aws:wafv2:us-east-1:123456789012:waf-status",
		"data": {
			"firewall_name": "my-firewall",
			"has_firewall_policy": false,
		},
	}
	count(result) == 0
}
