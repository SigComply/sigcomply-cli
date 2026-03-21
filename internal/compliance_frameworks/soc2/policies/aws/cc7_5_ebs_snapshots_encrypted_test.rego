package sigcomply.soc2.cc7_5_ebs_snapshots_encrypted_test

import data.sigcomply.soc2.cc7_5_ebs_snapshots_encrypted

test_not_encrypted if {
	result := cc7_5_ebs_snapshots_encrypted.violations with input as {
		"resource_type": "aws:ec2:ebs_snapshot",
		"resource_id": "snap-123",
		"data": {"snapshot_id": "snap-123", "encrypted": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := cc7_5_ebs_snapshots_encrypted.violations with input as {
		"resource_type": "aws:ec2:ebs_snapshot",
		"resource_id": "snap-123",
		"data": {"snapshot_id": "snap-123", "encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_5_ebs_snapshots_encrypted.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_5_ebs_snapshots_encrypted.violations with input as {
		"resource_type": "aws:ec2:ebs_snapshot",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
