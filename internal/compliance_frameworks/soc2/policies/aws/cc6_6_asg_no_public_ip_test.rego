package sigcomply.soc2.cc6_6_asg_no_public_ip_test

import data.sigcomply.soc2.cc6_6_asg_no_public_ip

# Test: public IP assignment enabled should violate
test_public_ip_assigned if {
	result := cc6_6_asg_no_public_ip.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/dev-asg",
		"data": {
			"group_name": "dev-asg",
			"associate_public_ip": true,
		},
	}
	count(result) == 1
}

# Test: no public IP assignment should pass
test_no_public_ip if {
	result := cc6_6_asg_no_public_ip.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/prod-asg",
		"data": {
			"group_name": "prod-asg",
			"associate_public_ip": false,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := cc6_6_asg_no_public_ip.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2:us-east-1:123:instance/i-abc",
		"data": {"associate_public_ip": true},
	}
	count(result) == 0
}
