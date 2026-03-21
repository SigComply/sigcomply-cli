package sigcomply.soc2.cc6_6_ec2_stopped_instances_test

import data.sigcomply.soc2.cc6_6_ec2_stopped_instances

# Test: stopped for 31 days should violate
test_stopped_too_long if {
	result := cc6_6_ec2_stopped_instances.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-123",
		"data": {
			"instance_id": "i-123",
			"state": "stopped",
			"days_since_stopped": 31,
		},
	}
	count(result) == 1
}

# Test: stopped for 30 days should pass (threshold is >30)
test_exactly_30_days if {
	result := cc6_6_ec2_stopped_instances.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-456",
		"data": {
			"instance_id": "i-456",
			"state": "stopped",
			"days_since_stopped": 30,
		},
	}
	count(result) == 0
}

# Test: running instance should pass
test_running if {
	result := cc6_6_ec2_stopped_instances.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-789",
		"data": {
			"instance_id": "i-789",
			"state": "running",
			"days_since_stopped": 0,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_ec2_stopped_instances.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"state": "stopped", "days_since_stopped": 50},
	}
	count(result) == 0
}
