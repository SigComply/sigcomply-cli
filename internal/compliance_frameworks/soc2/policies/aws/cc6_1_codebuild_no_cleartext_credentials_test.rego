package sigcomply.soc2.cc6_1_codebuild_no_cleartext_credentials_test

import data.sigcomply.soc2.cc6_1_codebuild_no_cleartext_credentials

# Test: project with cleartext credentials should violate
test_cleartext_credentials if {
	result := cc6_1_codebuild_no_cleartext_credentials.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/insecure-build",
		"data": {
			"name": "insecure-build",
			"cleartext_credentials": true,
		},
	}
	count(result) == 1
}

# Test: project without cleartext credentials should pass
test_no_cleartext_credentials if {
	result := cc6_1_codebuild_no_cleartext_credentials.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/secure-build",
		"data": {
			"name": "secure-build",
			"cleartext_credentials": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_codebuild_no_cleartext_credentials.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"cleartext_credentials": true},
	}
	count(result) == 0
}
