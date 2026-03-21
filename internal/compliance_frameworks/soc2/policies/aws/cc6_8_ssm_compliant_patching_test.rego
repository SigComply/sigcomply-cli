package sigcomply.soc2.cc6_8_ssm_compliant_patching_test

import data.sigcomply.soc2.cc6_8_ssm_compliant_patching

test_not_compliant if {
	result := cc6_8_ssm_compliant_patching.violations with input as {
		"resource_type": "aws:ssm:managed-instance",
		"resource_id": "mi-123",
		"data": {"instance_id": "i-123", "patch_compliant": false},
	}
	count(result) == 1
}

test_compliant if {
	result := cc6_8_ssm_compliant_patching.violations with input as {
		"resource_type": "aws:ssm:managed-instance",
		"resource_id": "mi-123",
		"data": {"instance_id": "i-123", "patch_compliant": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_ssm_compliant_patching.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_8_ssm_compliant_patching.violations with input as {
		"resource_type": "aws:ssm:managed-instance",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
