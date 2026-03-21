package sigcomply.soc2.cc7_1_networkfirewall_logging_test

import data.sigcomply.soc2.cc7_1_networkfirewall_logging

test_logging_disabled if {
	result := cc7_1_networkfirewall_logging.violations with input as {
		"resource_type": "aws:networkfirewall:firewall",
		"resource_id": "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall",
		"data": {
			"firewall_name": "my-firewall",
			"arn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall",
			"logging_enabled": false,
			"deletion_protection": true,
			"has_firewall_policy": true,
		},
	}
	count(result) == 1
}

test_logging_enabled if {
	result := cc7_1_networkfirewall_logging.violations with input as {
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
	result := cc7_1_networkfirewall_logging.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"firewall_name": "my-firewall",
			"logging_enabled": false,
		},
	}
	count(result) == 0
}
