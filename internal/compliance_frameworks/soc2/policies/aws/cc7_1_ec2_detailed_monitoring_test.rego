package sigcomply.soc2.cc7_1_ec2_detailed_monitoring_test

import data.sigcomply.soc2.cc7_1_ec2_detailed_monitoring

# Test: detailed monitoring disabled should violate
test_detailed_monitoring_disabled if {
	result := cc7_1_ec2_detailed_monitoring.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-123",
		"data": {
			"instance_id": "i-123",
			"detailed_monitoring_enabled": false,
		},
	}
	count(result) == 1
}

# Test: detailed monitoring enabled should pass
test_detailed_monitoring_enabled if {
	result := cc7_1_ec2_detailed_monitoring.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-123",
		"data": {
			"instance_id": "i-123",
			"detailed_monitoring_enabled": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_1_ec2_detailed_monitoring.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"detailed_monitoring_enabled": false,
		},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc7_1_ec2_detailed_monitoring.violations with input as {
		"resource_type": "aws:ec2:instance",
		"resource_id": "arn:aws:ec2::123:instance/i-123",
		"data": {},
	}
	count(result) == 0
}
