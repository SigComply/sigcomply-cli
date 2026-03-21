package sigcomply.soc2.cc6_2_route53_dnssec_test

import data.sigcomply.soc2.cc6_2_route53_dnssec

test_no_dnssec_public if {
	result := cc6_2_route53_dnssec.violations with input as {
		"resource_type": "aws:route53:hosted-zone",
		"resource_id": "arn:aws:route53:::hostedzone/Z123",
		"data": {"zone_name": "example.com.", "is_private": false, "dnssec_signing": false},
	}
	count(result) == 1
}

test_dnssec_enabled if {
	result := cc6_2_route53_dnssec.violations with input as {
		"resource_type": "aws:route53:hosted-zone",
		"resource_id": "arn:aws:route53:::hostedzone/Z123",
		"data": {"zone_name": "example.com.", "is_private": false, "dnssec_signing": true},
	}
	count(result) == 0
}

test_private_zone_no_dnssec if {
	result := cc6_2_route53_dnssec.violations with input as {
		"resource_type": "aws:route53:hosted-zone",
		"resource_id": "arn:aws:route53:::hostedzone/Z123",
		"data": {"zone_name": "internal.com.", "is_private": true, "dnssec_signing": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_2_route53_dnssec.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
