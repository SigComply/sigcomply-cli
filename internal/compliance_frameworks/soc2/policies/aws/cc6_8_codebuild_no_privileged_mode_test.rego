package sigcomply.soc2.cc6_8_codebuild_no_privileged_mode_test

import data.sigcomply.soc2.cc6_8_codebuild_no_privileged_mode

# Test: project with privileged mode should violate
test_privileged_mode if {
	result := cc6_8_codebuild_no_privileged_mode.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/privileged-build",
		"data": {
			"name": "privileged-build",
			"privileged_mode": true,
		},
	}
	count(result) == 1
}

# Test: project without privileged mode should pass
test_no_privileged_mode if {
	result := cc6_8_codebuild_no_privileged_mode.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/normal-build",
		"data": {
			"name": "normal-build",
			"privileged_mode": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_8_codebuild_no_privileged_mode.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"privileged_mode": true},
	}
	count(result) == 0
}
