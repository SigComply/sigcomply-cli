package sigcomply.soc2.a1_2_versioning_test

import data.sigcomply.soc2.a1_2_versioning

# Test: S3 bucket without versioning should violate
test_s3_no_versioning if {
	result := a1_2_versioning.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::my-bucket",
		"data": {
			"name": "my-bucket",
			"versioning_enabled": false,
		},
	}
	count(result) == 1
}

# Test: S3 bucket with versioning should pass
test_s3_versioning if {
	result := a1_2_versioning.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::versioned-bucket",
		"data": {
			"name": "versioned-bucket",
			"versioning_enabled": true,
		},
	}
	count(result) == 0
}

# Test: GCP bucket without versioning should violate
test_gcp_no_versioning if {
	result := a1_2_versioning.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/my-bucket",
		"data": {
			"name": "my-bucket",
			"versioning_enabled": false,
		},
	}
	count(result) == 1
}

# Test: GCP bucket with versioning should pass
test_gcp_versioning if {
	result := a1_2_versioning.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/versioned",
		"data": {
			"name": "versioned",
			"versioning_enabled": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := a1_2_versioning.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:db",
		"data": {"versioning_enabled": false},
	}
	count(result) == 0
}

# Negative: empty data for S3
test_s3_empty_data if {
	result := a1_2_versioning.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: empty data for GCP
test_gcp_empty_data if {
	result := a1_2_versioning.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/empty",
		"data": {},
	}
	count(result) == 0
}
