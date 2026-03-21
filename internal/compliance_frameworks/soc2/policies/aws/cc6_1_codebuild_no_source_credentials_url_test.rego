package sigcomply.soc2.cc6_1_codebuild_no_source_credentials_url_test

import data.sigcomply.soc2.cc6_1_codebuild_no_source_credentials_url

# Test: project with source credentials in URL should violate
test_source_credentials_in_url if {
	result := cc6_1_codebuild_no_source_credentials_url.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/insecure-source",
		"data": {
			"name": "insecure-source",
			"source_credentials_in_url": true,
		},
	}
	count(result) == 1
}

# Test: project without source credentials in URL should pass
test_no_source_credentials_in_url if {
	result := cc6_1_codebuild_no_source_credentials_url.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/secure-source",
		"data": {
			"name": "secure-source",
			"source_credentials_in_url": false,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_codebuild_no_source_credentials_url.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"source_credentials_in_url": true},
	}
	count(result) == 0
}
