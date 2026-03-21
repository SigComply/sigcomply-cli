package sigcomply.soc2.pi1_5_ebs_encryption_test

import data.sigcomply.soc2.pi1_5_ebs_encryption

test_not_encrypted if {
	result := pi1_5_ebs_encryption.violations with input as {
		"resource_type": "aws:ec2:volume",
		"resource_id": "vol-123",
		"data": {"encrypted": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := pi1_5_ebs_encryption.violations with input as {
		"resource_type": "aws:ec2:volume",
		"resource_id": "vol-123",
		"data": {"encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := pi1_5_ebs_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::test",
		"data": {"encrypted": false},
	}
	count(result) == 0
}
