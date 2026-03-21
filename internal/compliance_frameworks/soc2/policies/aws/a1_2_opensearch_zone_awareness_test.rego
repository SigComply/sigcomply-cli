package sigcomply.soc2.a1_2_opensearch_zone_awareness_test

import data.sigcomply.soc2.a1_2_opensearch_zone_awareness

test_zone_awareness_disabled if {
	result := a1_2_opensearch_zone_awareness.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"zone_awareness_enabled": false,
		},
	}
	count(result) == 1
}

test_zone_awareness_enabled if {
	result := a1_2_opensearch_zone_awareness.violations with input as {
		"resource_type": "aws:opensearch:domain",
		"resource_id": "arn:aws:es:us-east-1:123:domain/prod-search",
		"data": {
			"domain_name": "prod-search",
			"zone_awareness_enabled": true,
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := a1_2_opensearch_zone_awareness.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"zone_awareness_enabled": false},
	}
	count(result) == 0
}
