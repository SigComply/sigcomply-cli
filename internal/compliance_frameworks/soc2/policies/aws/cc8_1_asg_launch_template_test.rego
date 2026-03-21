package sigcomply.soc2.cc8_1_asg_launch_template_test

import data.sigcomply.soc2.cc8_1_asg_launch_template

# Test: launch configuration (no launch template) should violate
test_no_launch_template if {
	result := cc8_1_asg_launch_template.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/legacy-asg",
		"data": {
			"group_name": "legacy-asg",
			"uses_launch_template": false,
		},
	}
	count(result) == 1
}

# Test: launch template configured should pass
test_uses_launch_template if {
	result := cc8_1_asg_launch_template.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/prod-asg",
		"data": {
			"group_name": "prod-asg",
			"uses_launch_template": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := cc8_1_asg_launch_template.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2:us-east-1:123:instance/i-abc",
		"data": {"uses_launch_template": false},
	}
	count(result) == 0
}
