package sigcomply.soc2.cc6_6_open_ports_test

import data.sigcomply.soc2.cc6_6_open_ports

# Test: AWS SG with open SSH should violate
test_aws_open_ssh if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-123",
		"data": {
			"group_id": "sg-123",
			"group_name": "open-ssh",
			"open_ssh": true,
			"open_rdp": false,
		},
	}
	count(result) == 1
}

# Test: AWS SG with open RDP should violate
test_aws_open_rdp if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-456",
		"data": {
			"group_id": "sg-456",
			"group_name": "open-rdp",
			"open_ssh": false,
			"open_rdp": true,
		},
	}
	count(result) == 1
}

# Test: AWS SG with both open should have 2 violations
test_aws_both_open if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-789",
		"data": {
			"group_id": "sg-789",
			"group_name": "all-open",
			"open_ssh": true,
			"open_rdp": true,
		},
	}
	count(result) == 2
}

# Test: AWS SG with no open ports should pass
test_aws_restricted if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-safe",
		"data": {
			"group_id": "sg-safe",
			"group_name": "restricted",
			"open_ssh": false,
			"open_rdp": false,
		},
	}
	count(result) == 0
}

# Test: GCP firewall with open SSH should violate
test_gcp_open_ssh if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "gcp:compute:firewall",
		"resource_id": "projects/proj/global/firewalls/allow-ssh",
		"data": {
			"name": "allow-ssh",
			"open_ssh": true,
			"open_rdp": false,
			"disabled": false,
		},
	}
	count(result) == 1
}

# Test: GCP disabled firewall with open SSH should pass
test_gcp_disabled_firewall if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "gcp:compute:firewall",
		"resource_id": "projects/proj/global/firewalls/disabled-rule",
		"data": {
			"name": "disabled-rule",
			"open_ssh": true,
			"open_rdp": true,
			"disabled": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type should not trigger
test_wrong_resource_type if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"open_ssh": true,
			"open_rdp": true,
		},
	}
	count(result) == 0
}

# Negative: empty data for AWS SG should not trigger
test_aws_empty_data if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "aws:ec2:security-group",
		"resource_id": "arn:aws:ec2::123:security-group/sg-empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: empty data for GCP firewall should not trigger
test_gcp_empty_data if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "gcp:compute:firewall",
		"resource_id": "projects/proj/global/firewalls/empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: GCP firewall with open SSH but missing disabled field
test_gcp_missing_disabled_field if {
	result := cc6_6_open_ports.violations with input as {
		"resource_type": "gcp:compute:firewall",
		"resource_id": "projects/proj/global/firewalls/no-disabled",
		"data": {
			"name": "no-disabled",
			"open_ssh": true,
		},
	}
	count(result) == 0
}
