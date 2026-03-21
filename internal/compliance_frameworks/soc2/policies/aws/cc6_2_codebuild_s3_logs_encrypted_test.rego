package sigcomply.soc2.cc6_2_codebuild_s3_logs_encrypted_test

import data.sigcomply.soc2.cc6_2_codebuild_s3_logs_encrypted

# Test: project with unencrypted S3 logs should violate
test_s3_logs_not_encrypted if {
	result := cc6_2_codebuild_s3_logs_encrypted.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/unencrypted-logs",
		"data": {
			"name": "unencrypted-logs",
			"s3_logs_encrypted": false,
		},
	}
	count(result) == 1
}

# Test: project with encrypted S3 logs should pass
test_s3_logs_encrypted if {
	result := cc6_2_codebuild_s3_logs_encrypted.violations with input as {
		"resource_type": "aws:codebuild:project",
		"resource_id": "arn:aws:codebuild:us-east-1:123:project/encrypted-logs",
		"data": {
			"name": "encrypted-logs",
			"s3_logs_encrypted": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_codebuild_s3_logs_encrypted.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"s3_logs_encrypted": false},
	}
	count(result) == 0
}
