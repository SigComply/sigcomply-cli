package sigcomply.soc2.cc6_1_redshift_no_default_admin_test

import data.sigcomply.soc2.cc6_1_redshift_no_default_admin

# Test: default username 'admin' should violate
test_default_admin if {
	result := cc6_1_redshift_no_default_admin.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:my-cluster",
		"data": {
			"cluster_id": "my-cluster",
			"master_username": "admin",
		},
	}
	count(result) == 1
}

# Test: default username 'awsuser' should violate
test_default_awsuser if {
	result := cc6_1_redshift_no_default_admin.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:my-cluster",
		"data": {
			"cluster_id": "my-cluster",
			"master_username": "awsuser",
		},
	}
	count(result) == 1
}

# Test: default username 'root' should violate
test_default_root if {
	result := cc6_1_redshift_no_default_admin.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:my-cluster",
		"data": {
			"cluster_id": "my-cluster",
			"master_username": "root",
		},
	}
	count(result) == 1
}

# Test: custom username should pass
test_custom_username if {
	result := cc6_1_redshift_no_default_admin.violations with input as {
		"resource_type": "aws:redshift:cluster",
		"resource_id": "arn:aws:redshift:us-east-1:123:cluster:my-cluster",
		"data": {
			"cluster_id": "my-cluster",
			"master_username": "mydbadmin",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_1_redshift_no_default_admin.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"master_username": "admin"},
	}
	count(result) == 0
}
