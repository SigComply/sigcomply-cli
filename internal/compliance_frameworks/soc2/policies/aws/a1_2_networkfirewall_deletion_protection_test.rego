package sigcomply.soc2.a1_2_networkfirewall_deletion_protection_test

import data.sigcomply.soc2.a1_2_networkfirewall_deletion_protection

test_deletion_protection_disabled if {
	result := a1_2_networkfirewall_deletion_protection.violations with input as {
		"resource_type": "aws:networkfirewall:firewall",
		"resource_id": "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall",
		"data": {
			"firewall_name": "my-firewall",
			"arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall",
			"logging_enabled": true,
			"deletion_protection": false,
			"has_firewall_policy": true,
		},
	}
	count(result) == 1
}

test_deletion_protection_enabled if {
	result := a1_2_networkfirewall_deletion_protection.violations with input as {
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
	result := a1_2_networkfirewall_deletion_protection.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "i-1234567890abcdef0",
		"data": {
			"firewall_name": "my-firewall",
			"deletion_protection": false,
		},
	}
	count(result) == 0
}
