package sigcomply.soc2.cc6_1_asg_imdsv2_test

import data.sigcomply.soc2.cc6_1_asg_imdsv2

# Test: IMDSv2 not required should violate
test_imdsv2_not_required if {
	result := cc6_1_asg_imdsv2.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/prod-asg",
		"data": {
			"group_name": "prod-asg",
			"imdsv2_required": false,
			"uses_launch_template": true,
		},
	}
	count(result) == 1
}

# Test: IMDSv2 required should pass
test_imdsv2_required if {
	result := cc6_1_asg_imdsv2.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/prod-asg",
		"data": {
			"group_name": "prod-asg",
			"imdsv2_required": true,
			"uses_launch_template": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := cc6_1_asg_imdsv2.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2:us-east-1:123:instance/i-abc",
		"data": {"imdsv2_required": false},
	}
	count(result) == 0
}
