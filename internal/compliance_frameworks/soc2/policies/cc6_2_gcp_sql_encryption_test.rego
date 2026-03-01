package sigcomply.soc2.cc6_2_gcp_sql_test

import data.sigcomply.soc2.cc6_2_gcp_sql

# Test: SQL with Google-managed encryption (no CMEK) should violate (low severity)
test_google_managed if {
	result := cc6_2_gcp_sql.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/db-1",
		"data": {
			"name": "db-1",
			"encryption_enabled": true,
		},
	}
	count(result) == 1
}

# Test: SQL with CMEK should pass
test_cmek if {
	result := cc6_2_gcp_sql.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/db-2",
		"data": {
			"name": "db-2",
			"encryption_enabled": true,
			"kms_key_name": "projects/proj/locations/us/keyRings/ring/cryptoKeys/key",
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_2_gcp_sql.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:db",
		"data": {"encryption_enabled": true},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_2_gcp_sql.violations with input as {
		"resource_type": "gcp:sql:instance",
		"resource_id": "projects/proj/instances/empty",
		"data": {},
	}
	count(result) == 0
}
