package sigcomply.soc2.cc1_5_organizations_scps_test

import data.sigcomply.soc2.cc1_5_organizations_scps

# Test: SCPs enabled should pass
test_scps_enabled if {
	result := cc1_5_organizations_scps.violations with input as {
		"resource_type": "aws:organizations:status",
		"resource_id": "arn:aws:organizations::123:status",
		"data": {
			"is_organization_member": true,
			"scp_enabled": true,
			"scp_count": 2,
		},
	}
	count(result) == 0
}

# Test: in org but SCPs disabled should violate
test_scps_disabled if {
	result := cc1_5_organizations_scps.violations with input as {
		"resource_type": "aws:organizations:status",
		"resource_id": "arn:aws:organizations::123:status",
		"data": {
			"is_organization_member": true,
			"scp_enabled": false,
			"scp_count": 0,
		},
	}
	count(result) == 1
}

# Test: not in org should pass (no violation)
test_not_in_org if {
	result := cc1_5_organizations_scps.violations with input as {
		"resource_type": "aws:organizations:status",
		"resource_id": "arn:aws:organizations::123:status",
		"data": {
			"is_organization_member": false,
			"scp_enabled": false,
			"scp_count": 0,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc1_5_organizations_scps.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {
			"is_organization_member": true,
			"scp_enabled": false,
		},
	}
	count(result) == 0
}

# Negative: empty data
test_empty_data if {
	result := cc1_5_organizations_scps.violations with input as {
		"resource_type": "aws:organizations:status",
		"resource_id": "arn:aws:organizations::123:status",
		"data": {},
	}
	count(result) == 0
}
