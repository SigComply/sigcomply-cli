package sigcomply.soc2.cc6_7_dax_tls_test

import data.sigcomply.soc2.cc6_7_dax_tls

test_no_tls if {
	result := cc6_7_dax_tls.violations with input as {
		"resource_type": "aws:dax:cluster",
		"resource_id": "arn:aws:dax:us-east-1:123:cache/cluster",
		"data": {"name": "cluster", "cluster_endpoint_encryption_type": "NONE"},
	}
	count(result) == 1
}

test_tls_enabled if {
	result := cc6_7_dax_tls.violations with input as {
		"resource_type": "aws:dax:cluster",
		"resource_id": "arn:aws:dax:us-east-1:123:cache/cluster",
		"data": {"name": "cluster", "cluster_endpoint_encryption_type": "TLS"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_dax_tls.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
