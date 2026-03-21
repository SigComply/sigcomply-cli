package sigcomply.soc2.cc6_7_cloudfront_tls_test

import data.sigcomply.soc2.cc6_7_cloudfront_tls

test_outdated_sslv3_violation if {
	result := cc6_7_cloudfront_tls.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "minimum_protocol_version": "SSLv3"},
	}
	count(result) == 1
}

test_outdated_tlsv1_violation if {
	result := cc6_7_cloudfront_tls.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "minimum_protocol_version": "TLSv1"},
	}
	count(result) == 1
}

test_outdated_tlsv1_2016_violation if {
	result := cc6_7_cloudfront_tls.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "minimum_protocol_version": "TLSv1_2016"},
	}
	count(result) == 1
}

test_outdated_tlsv11_2016_violation if {
	result := cc6_7_cloudfront_tls.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "minimum_protocol_version": "TLSv1.1_2016"},
	}
	count(result) == 1
}

test_tlsv12_2018_pass if {
	result := cc6_7_cloudfront_tls.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "minimum_protocol_version": "TLSv1.2_2018"},
	}
	count(result) == 0
}

test_tlsv12_2021_pass if {
	result := cc6_7_cloudfront_tls.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {"domain_name": "d123.cloudfront.net", "minimum_protocol_version": "TLSv1.2_2021"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_7_cloudfront_tls.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"minimum_protocol_version": "SSLv3"},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_7_cloudfront_tls.violations with input as {
		"resource_type": "aws:cloudfront:distribution",
		"resource_id": "arn:aws:cloudfront::123:distribution/ABC",
		"data": {},
	}
	count(result) == 0
}
