package sigcomply.soc2.cc6_6_ec2_ebs_snapshot_block_public_test

import data.sigcomply.soc2.cc6_6_ec2_ebs_snapshot_block_public

test_not_blocked if {
	result := cc6_6_ec2_ebs_snapshot_block_public.violations with input as {
		"resource_type": "aws:ec2:account-setting",
		"resource_id": "ebs-settings",
		"data": {"ebs_block_public_access": false},
	}
	count(result) == 1
}

test_blocked if {
	result := cc6_6_ec2_ebs_snapshot_block_public.violations with input as {
		"resource_type": "aws:ec2:account-setting",
		"resource_id": "ebs-settings",
		"data": {"ebs_block_public_access": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_ec2_ebs_snapshot_block_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_ec2_ebs_snapshot_block_public.violations with input as {
		"resource_type": "aws:ec2:account-setting",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
