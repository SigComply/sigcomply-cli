package sigcomply.soc2.cc6_1_ec2_imdsv2_launch_template_test

import data.sigcomply.soc2.cc6_1_ec2_imdsv2_launch_template

# Test: HttpTokens not required should violate
test_not_required if {
	result := cc6_1_ec2_imdsv2_launch_template.violations with input as {
		"resource_type": "aws:ec2:launch-template",
		"resource_id": "arn:aws:ec2::123:launch-template/lt-123",
		"data": {
			"launch_template_name": "my-template",
			"launch_template_id": "lt-123",
			"http_tokens": "optional",
		},
	}
	count(result) == 1
}

# Test: HttpTokens required should pass
test_required if {
	result := cc6_1_ec2_imdsv2_launch_template.violations with input as {
		"resource_type": "aws:ec2:launch-template",
		"resource_id": "arn:aws:ec2::123:launch-template/lt-456",
		"data": {
			"launch_template_name": "secure-template",
			"launch_template_id": "lt-456",
			"http_tokens": "required",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_ec2_imdsv2_launch_template.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"http_tokens": "optional"},
	}
	count(result) == 0
}
