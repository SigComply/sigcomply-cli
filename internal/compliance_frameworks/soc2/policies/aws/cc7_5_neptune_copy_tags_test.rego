package sigcomply.soc2.cc7_5_neptune_copy_tags_test

import data.sigcomply.soc2.cc7_5_neptune_copy_tags

test_no_copy_tags if {
	result := cc7_5_neptune_copy_tags.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:neptune:us-east-1:123:cluster/mycluster",
		"data": {"cluster_id": "mycluster", "copy_tags_to_snapshot": false},
	}
	count(result) == 1
}

test_copy_tags_enabled if {
	result := cc7_5_neptune_copy_tags.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "arn:aws:neptune:us-east-1:123:cluster/mycluster",
		"data": {"cluster_id": "mycluster", "copy_tags_to_snapshot": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_5_neptune_copy_tags.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_5_neptune_copy_tags.violations with input as {
		"resource_type": "aws:neptune:cluster",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
