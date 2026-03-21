package sigcomply.soc2.cc7_2_guardduty_runtime_monitoring_test

import data.sigcomply.soc2.cc7_2_guardduty_runtime_monitoring

# Test: Runtime monitoring disabled should violate
test_runtime_monitoring_disabled if {
	result := cc7_2_guardduty_runtime_monitoring.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "arn:aws:guardduty:us-east-1:123:detector/abc",
		"data": {
			"enabled": true,
			"runtime_monitoring_enabled": false,
			"region": "us-east-1",
			"detector_id": "abc",
		},
	}
	count(result) == 1
}

# Test: Runtime monitoring enabled should pass
test_runtime_monitoring_enabled if {
	result := cc7_2_guardduty_runtime_monitoring.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "arn:aws:guardduty:us-east-1:123:detector/abc",
		"data": {
			"enabled": true,
			"runtime_monitoring_enabled": true,
			"region": "us-east-1",
			"detector_id": "abc",
		},
	}
	count(result) == 0
}

# Test: GuardDuty disabled should not trigger
test_guardduty_disabled if {
	result := cc7_2_guardduty_runtime_monitoring.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "arn:aws:guardduty:us-east-1:123:detector/abc",
		"data": {
			"enabled": false,
			"runtime_monitoring_enabled": false,
			"region": "us-east-1",
			"detector_id": "abc",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_2_guardduty_runtime_monitoring.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": true, "runtime_monitoring_enabled": false},
	}
	count(result) == 0
}
