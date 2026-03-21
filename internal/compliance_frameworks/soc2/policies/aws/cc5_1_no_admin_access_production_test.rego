package sigcomply.soc2.cc5_1_no_admin_access_production_test

import data.sigcomply.soc2.cc5_1_no_admin_access_production

# Test: role with AdministratorAccess should violate
test_admin_access if {
	result := cc5_1_no_admin_access_production.violations with input as {
		"resource_type": "aws:iam:role",
		"resource_id": "arn:aws:iam::123:role/AdminRole",
		"data": {
			"role_name": "AdminRole",
			"has_admin_access": true,
			"attached_policies": ["AdministratorAccess"],
		},
	}
	count(result) == 1
}

# Test: role without AdministratorAccess should pass
test_no_admin_access if {
	result := cc5_1_no_admin_access_production.violations with input as {
		"resource_type": "aws:iam:role",
		"resource_id": "arn:aws:iam::123:role/AppRole",
		"data": {
			"role_name": "AppRole",
			"has_admin_access": false,
			"attached_policies": ["AmazonS3ReadOnlyAccess"],
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc5_1_no_admin_access_production.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"has_admin_access": true},
	}
	count(result) == 0
}
