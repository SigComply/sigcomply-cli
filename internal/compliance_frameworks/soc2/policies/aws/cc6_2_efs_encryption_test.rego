package sigcomply.soc2.cc6_2_efs_encryption_test

import data.sigcomply.soc2.cc6_2_efs_encryption

test_unencrypted_efs if {
	result := cc6_2_efs_encryption.violations with input as {
		"resource_type": "aws:efs:file_system",
		"resource_id": "arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-123",
		"data": {
			"file_system_id": "fs-123",
			"name": "prod-efs",
			"encrypted": false,
		},
	}
	count(result) == 1
}

test_encrypted_efs if {
	result := cc6_2_efs_encryption.violations with input as {
		"resource_type": "aws:efs:file_system",
		"resource_id": "arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-123",
		"data": {
			"file_system_id": "fs-123",
			"name": "prod-efs",
			"encrypted": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_efs_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"encrypted": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_efs_encryption.violations with input as {
		"resource_type": "aws:efs:file_system",
		"resource_id": "arn:aws:elasticfilesystem:us-east-1:123:file-system/fs-test",
		"data": {},
	}
	count(result) == 0
}
