package sigcomply.soc2.cc6_2_ebs_snapshot_encryption_test

import data.sigcomply.soc2.cc6_2_ebs_snapshot_encryption

# Test: unencrypted snapshot should violate
test_unencrypted if {
	result := cc6_2_ebs_snapshot_encryption.violations with input as {
		"resource_type": "aws:ec2:ebs_snapshot",
		"resource_id": "arn:aws:ec2::123:snapshot/snap-123",
		"data": {
			"snapshot_id": "snap-123",
			"volume_id": "vol-123",
			"encrypted": false,
		},
	}
	count(result) == 1
}

# Test: encrypted snapshot should pass
test_encrypted if {
	result := cc6_2_ebs_snapshot_encryption.violations with input as {
		"resource_type": "aws:ec2:ebs_snapshot",
		"resource_id": "arn:aws:ec2::123:snapshot/snap-456",
		"data": {
			"snapshot_id": "snap-456",
			"volume_id": "vol-456",
			"encrypted": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_ebs_snapshot_encryption.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"encrypted": false},
	}
	count(result) == 0
}
