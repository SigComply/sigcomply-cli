package sigcomply.soc2.cc6_2_s3_no_acl_test

import data.sigcomply.soc2.cc6_2_s3_no_acl

# Test: ACLs enabled should violate
test_acls_enabled if {
	result := cc6_2_s3_no_acl.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"bucket_name": "my-bucket",
			"acls_enabled": true,
			"object_ownership": "BucketOwnerPreferred",
		},
	}
	count(result) == 1
}

# Test: ACLs disabled should pass
test_acls_disabled if {
	result := cc6_2_s3_no_acl.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"bucket_name": "my-bucket",
			"acls_enabled": false,
			"object_ownership": "BucketOwnerEnforced",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_s3_no_acl.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds::123:db:mydb",
		"data": {"acls_enabled": true},
	}
	count(result) == 0
}
