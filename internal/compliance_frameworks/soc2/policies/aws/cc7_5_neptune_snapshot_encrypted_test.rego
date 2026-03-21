package sigcomply.soc2.cc7_5_neptune_snapshot_encrypted_test

import data.sigcomply.soc2.cc7_5_neptune_snapshot_encrypted

test_not_encrypted if {
	result := cc7_5_neptune_snapshot_encrypted.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:neptune:us-east-1:123:cluster/mycluster",
		"data": {"cluster_id": "mycluster", "storage_encrypted": false},
	}
	count(result) == 1
}

test_encrypted if {
	result := cc7_5_neptune_snapshot_encrypted.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:neptune:us-east-1:123:cluster/mycluster",
		"data": {"cluster_id": "mycluster", "storage_encrypted": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_5_neptune_snapshot_encrypted.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_5_neptune_snapshot_encrypted.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
