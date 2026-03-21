package sigcomply.soc2.cc7_5_ebs_snapshots_exist_test

import data.sigcomply.soc2.cc7_5_ebs_snapshots_exist

test_no_snapshots if {
	result := cc7_5_ebs_snapshots_exist.violations with input as {
		"resource_type": "aws:ec2:volume",
		"resource_id": "vol-123",
		"data": {"has_snapshots": false},
	}
	count(result) == 1
}

test_has_snapshots if {
	result := cc7_5_ebs_snapshots_exist.violations with input as {
		"resource_type": "aws:ec2:volume",
		"resource_id": "vol-123",
		"data": {"has_snapshots": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_5_ebs_snapshots_exist.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_5_ebs_snapshots_exist.violations with input as {
		"resource_type": "aws:ec2:volume",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
