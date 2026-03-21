package sigcomply.soc2.cc6_1_ec2_imdsv2_test

import data.sigcomply.soc2.cc6_1_ec2_imdsv2

# Test: IMDSv2 not required should violate
test_imdsv2_optional if {
	result := cc6_1_ec2_imdsv2.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-123",
		"data": {
			"instance_id": "i-123",
			"http_tokens": "optional",
			"http_endpoint": "enabled",
		},
	}
	count(result) == 1
}

# Test: IMDSv2 required should pass
test_imdsv2_required if {
	result := cc6_1_ec2_imdsv2.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-123",
		"data": {
			"instance_id": "i-123",
			"http_tokens": "required",
			"http_endpoint": "enabled",
		},
	}
	count(result) == 0
}

# Test: endpoint disabled should not violate (no IMDS at all)
test_endpoint_disabled if {
	result := cc6_1_ec2_imdsv2.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-123",
		"data": {
			"instance_id": "i-123",
			"http_tokens": "disabled",
			"http_endpoint": "disabled",
		},
	}
	count(result) == 1
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_ec2_imdsv2.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"http_tokens": "optional"},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_1_ec2_imdsv2.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-123",
		"data": {},
	}
	count(result) == 0
}
