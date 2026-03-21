package sigcomply.soc2.a1_2_asg_elb_health_check_test

import data.sigcomply.soc2.a1_2_asg_elb_health_check

# Test: EC2 health check should violate
test_ec2_health_check if {
	result := a1_2_asg_elb_health_check.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/prod-asg",
		"data": {
			"group_name": "prod-asg",
			"elb_health_check": false,
			"multi_az": true,
		},
	}
	count(result) == 1
}

# Test: ELB health check should pass
test_elb_health_check if {
	result := a1_2_asg_elb_health_check.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/prod-asg",
		"data": {
			"group_name": "prod-asg",
			"elb_health_check": true,
			"multi_az": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := a1_2_asg_elb_health_check.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2:us-east-1:123:instance/i-abc123",
		"data": {"elb_health_check": false},
	}
	count(result) == 0
}
