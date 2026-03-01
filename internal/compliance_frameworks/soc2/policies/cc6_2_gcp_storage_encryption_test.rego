package sigcomply.soc2.cc6_2_gcp_storage_test

import data.sigcomply.soc2.cc6_2_gcp_storage

# Test: bucket with Google-managed encryption (no CMEK) should violate (low severity)
test_google_managed if {
	result := cc6_2_gcp_storage.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/my-bucket",
		"data": {
			"name": "my-bucket",
			"encryption_enabled": true,
		},
	}
	count(result) == 1
}

# Test: bucket with CMEK should pass
test_cmek if {
	result := cc6_2_gcp_storage.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/secure-bucket",
		"data": {
			"name": "secure-bucket",
			"encryption_enabled": true,
			"default_kms_key_name": "projects/proj/locations/us/keyRings/ring/cryptoKeys/key",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_gcp_storage.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"encryption_enabled": true},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_gcp_storage.violations with input as {
		"resource_type": "gcp:storage:bucket",
		"resource_id": "projects/proj/buckets/empty",
		"data": {},
	}
	count(result) == 0
}
