package sigcomply.soc2.cc6_6_ec2_launch_template_no_public_ip_test

import data.sigcomply.soc2.cc6_6_ec2_launch_template_no_public_ip

test_public_ip if {
	result := cc6_6_ec2_launch_template_no_public_ip.violations with input as {
		"resource_type": "aws:ec2:launch-template",
		"resource_id": "lt-123",
		"data": {"name": "my-template", "assigns_public_ip": true},
	}
	count(result) == 1
}

test_no_public_ip if {
	result := cc6_6_ec2_launch_template_no_public_ip.violations with input as {
		"resource_type": "aws:ec2:launch-template",
		"resource_id": "lt-123",
		"data": {"name": "my-template", "assigns_public_ip": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_ec2_launch_template_no_public_ip.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_ec2_launch_template_no_public_ip.violations with input as {
		"resource_type": "aws:ec2:launch-template",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
