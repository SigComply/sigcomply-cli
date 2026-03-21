package sigcomply.soc2.cc7_2_guardduty_eks_protection_test

import data.sigcomply.soc2.cc7_2_guardduty_eks_protection

# Test: EKS audit logs disabled should violate
test_eks_protection_disabled if {
	result := cc7_2_guardduty_eks_protection.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "arn:aws:guardduty:us-east-1:123:detector/abc",
		"data": {
			"enabled": true,
			"eks_audit_logs_enabled": false,
			"region": "us-east-1",
			"detector_id": "abc",
		},
	}
	count(result) == 1
}

# Test: EKS audit logs enabled should pass
test_eks_protection_enabled if {
	result := cc7_2_guardduty_eks_protection.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "arn:aws:guardduty:us-east-1:123:detector/abc",
		"data": {
			"enabled": true,
			"eks_audit_logs_enabled": true,
			"region": "us-east-1",
			"detector_id": "abc",
		},
	}
	count(result) == 0
}

# Test: GuardDuty disabled should not trigger
test_guardduty_disabled if {
	result := cc7_2_guardduty_eks_protection.violations with input as {
		"resource_type": "aws:guardduty:detector",
		"resource_id": "arn:aws:guardduty:us-east-1:123:detector/abc",
		"data": {
			"enabled": false,
			"eks_audit_logs_enabled": false,
			"region": "us-east-1",
			"detector_id": "abc",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc7_2_guardduty_eks_protection.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": true, "eks_audit_logs_enabled": false},
	}
	count(result) == 0
}
