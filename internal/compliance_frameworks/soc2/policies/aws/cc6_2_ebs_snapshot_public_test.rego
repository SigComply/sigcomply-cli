package sigcomply.soc2.cc6_2_ebs_snapshot_public_test

import data.sigcomply.soc2.cc6_2_ebs_snapshot_public

test_public_snapshot if {
	result := cc6_2_ebs_snapshot_public.violations with input as {
		"resource_type": "aws:ec2:ebs_snapshot",
		"resource_id": "arn:aws:ec2::123:snapshot/snap-123",
		"data": {
			"snapshot_id": "snap-123",
			"volume_id": "vol-abc",
			"public": true,
		},
	}
	count(result) == 1
}

test_private_snapshot if {
	result := cc6_2_ebs_snapshot_public.violations with input as {
		"resource_type": "aws:ec2:ebs_snapshot",
		"resource_id": "arn:aws:ec2::123:snapshot/snap-456",
		"data": {
			"snapshot_id": "snap-456",
			"volume_id": "vol-def",
			"public": false,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_ebs_snapshot_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"public": true},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_2_ebs_snapshot_public.violations with input as {
		"resource_type": "aws:ec2:ebs_snapshot",
		"resource_id": "arn:aws:ec2::123:snapshot/snap-789",
		"data": {},
	}
	count(result) == 0
}
