package sigcomply.soc2.c1_1_macie_enabled_test

import data.sigcomply.soc2.c1_1_macie_enabled

test_macie_disabled if {
	result := c1_1_macie_enabled.violations with input as {
		"resource_type": "aws:macie2:session",
		"resource_id": "arn:aws:macie2:us-east-1:123:session",
		"data": {"enabled": false, "region": "us-east-1"},
	}
	count(result) == 1
}

test_macie_enabled if {
	result := c1_1_macie_enabled.violations with input as {
		"resource_type": "aws:macie2:session",
		"resource_id": "arn:aws:macie2:us-east-1:123:session",
		"data": {"enabled": true, "region": "us-east-1"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := c1_1_macie_enabled.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"enabled": false},
	}
	count(result) == 0
}

test_empty_data if {
	result := c1_1_macie_enabled.violations with input as {
		"resource_type": "aws:macie2:session",
		"resource_id": "arn:aws:macie2:us-east-1:123:session",
		"data": {},
	}
	count(result) == 0
}
