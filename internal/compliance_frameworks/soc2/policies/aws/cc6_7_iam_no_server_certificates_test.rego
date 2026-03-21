package sigcomply.soc2.cc6_7_iam_no_server_certificates_test

import data.sigcomply.soc2.cc6_7_iam_no_server_certificates

# Test: having server certificates should violate
test_has_server_certificates if {
	result := cc6_7_iam_no_server_certificates.violations with input as {
		"resource_type": "aws:iam:server-certificate-status",
		"resource_id": "arn:aws:iam::123456789012:server-certificate-status",
		"data": {
			"has_server_certificates": true,
			"certificate_count": 2,
		},
	}
	count(result) == 1
}

# Test: no server certificates should pass
test_no_server_certificates if {
	result := cc6_7_iam_no_server_certificates.violations with input as {
		"resource_type": "aws:iam:server-certificate-status",
		"resource_id": "arn:aws:iam::123456789012:server-certificate-status",
		"data": {
			"has_server_certificates": false,
			"certificate_count": 0,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_7_iam_no_server_certificates.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123456789012:user/alice",
		"data": {"has_server_certificates": true, "certificate_count": 1},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc6_7_iam_no_server_certificates.violations with input as {
		"resource_type": "aws:iam:server-certificate-status",
		"resource_id": "arn:aws:iam::123456789012:server-certificate-status",
		"data": {},
	}
	count(result) == 0
}
