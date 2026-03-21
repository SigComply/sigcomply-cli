package sigcomply.soc2.cc6_2_fsx_encryption_test

import data.sigcomply.soc2.cc6_2_fsx_encryption

test_not_encrypted if {
	result := cc6_2_fsx_encryption.violations with input as {
		"resource_type": "aws:fsx:filesystem",
		"resource_id": "arn:aws:fsx:us-east-1:123:file-system/fs-abc",
		"data": {"file_system_id": "fs-abc", "encrypted": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := cc6_2_fsx_encryption.violations with input as {
		"resource_type": "aws:fsx:filesystem",
		"resource_id": "arn:aws:fsx:us-east-1:123:file-system/fs-abc",
		"data": {"file_system_id": "fs-abc", "encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_fsx_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
