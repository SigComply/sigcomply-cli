package sigcomply.soc2.cc6_2_gcp_storage_public_test

import data.sigcomply.soc2.cc6_2_gcp_storage_public

# Test: bucket with allUsers access should violate
test_all_users_access if {
	result := cc6_2_gcp_storage_public.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/public-bucket",
		"data": {
			"name": "public-bucket",
			"all_users_access": true,
			"all_authenticated_access": false,
			"uniform_bucket_access": true,
		},
	}
	count(result) == 1
}

# Test: bucket with allAuthenticatedUsers should violate
test_all_authenticated_access if {
	result := cc6_2_gcp_storage_public.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/semi-public",
		"data": {
			"name": "semi-public",
			"all_users_access": false,
			"all_authenticated_access": true,
			"uniform_bucket_access": true,
		},
	}
	count(result) == 1
}

# Test: bucket without uniform access should violate
test_no_uniform_access if {
	result := cc6_2_gcp_storage_public.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/legacy",
		"data": {
			"name": "legacy",
			"all_users_access": false,
			"all_authenticated_access": false,
			"uniform_bucket_access": false,
		},
	}
	count(result) == 1
}

# Test: secure bucket should pass
test_secure_bucket if {
	result := cc6_2_gcp_storage_public.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/secure",
		"data": {
			"name": "secure",
			"all_users_access": false,
			"all_authenticated_access": false,
			"uniform_bucket_access": true,
		},
	}
	count(result) == 0
}

# Test: bucket with all issues should have 3 violations
test_all_issues if {
	result := cc6_2_gcp_storage_public.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/worst-case",
		"data": {
			"name": "worst-case",
			"all_users_access": true,
			"all_authenticated_access": true,
			"uniform_bucket_access": false,
		},
	}
	count(result) == 3
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_gcp_storage_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"all_users_access": true, "all_authenticated_access": true, "uniform_bucket_access": false},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_gcp_storage_public.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/empty",
		"data": {},
	}
	count(result) == 0
}
