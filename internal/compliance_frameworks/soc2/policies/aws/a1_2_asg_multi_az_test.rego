package sigcomply.soc2.a1_2_asg_multi_az_test

import data.sigcomply.soc2.a1_2_asg_multi_az

# Test: single-AZ group should violate
test_single_az if {
	result := a1_2_asg_multi_az.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/dev-asg",
		"data": {
			"group_name": "dev-asg",
			"multi_az": false,
			"elb_health_check": true,
		},
	}
	count(result) == 1
}

# Test: multi-AZ group should pass
test_multi_az if {
	result := a1_2_asg_multi_az.violations with input as {
		"resource_type": "aws:autoscaling:group",
		"resource_id": "arn:aws:autoscaling:us-east-1:123:autoScalingGroup:abc:autoScalingGroupName/prod-asg",
		"data": {
			"group_name": "prod-asg",
			"multi_az": true,
			"elb_health_check": true,
		},
	}
	count(result) == 0
}

# Test: wrong resource type should not violate
test_wrong_resource_type if {
	result := a1_2_asg_multi_az.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {"multi_az": false},
	}
	count(result) == 0
}
