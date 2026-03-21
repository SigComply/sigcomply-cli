package sigcomply.soc2.cc7_2_rds_cluster_cloudwatch_test

import data.sigcomply.soc2.cc7_2_rds_cluster_cloudwatch

test_no_logs if {
	result := cc7_2_rds_cluster_cloudwatch.violations with input as {
		"resource_type": "aws:rds:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123:cluster/mycluster",
		"data": {"cluster_id": "mycluster", "enabled_cloudwatch_logs": false},
	}
	count(result) == 1
}

test_logs_enabled if {
	result := cc7_2_rds_cluster_cloudwatch.violations with input as {
		"resource_type": "aws:rds:cluster",
		"resource_id": "arn:aws:rds:us-east-1:123:cluster/mycluster",
		"data": {"cluster_id": "mycluster", "enabled_cloudwatch_logs": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_2_rds_cluster_cloudwatch.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_2_rds_cluster_cloudwatch.violations with input as {
		"resource_type": "aws:rds:cluster",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
