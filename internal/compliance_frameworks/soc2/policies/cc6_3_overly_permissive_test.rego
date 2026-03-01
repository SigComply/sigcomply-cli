package sigcomply.soc2.cc6_3_permissive_test

import data.sigcomply.soc2.cc6_3_permissive

# Test: owner role should violate
test_owner_role if {
	result := cc6_3_permissive.violations with input as {
		"resource_type": "gcp:iam:policy",
		"resource_id": "my-project",
		"data": {
			"bindings": [
				{"role": "roles/owner", "members": ["user:admin@example.com"]},
			],
		},
	}
	count(result) == 1
}

# Test: editor role should violate
test_editor_role if {
	result := cc6_3_permissive.violations with input as {
		"resource_type": "gcp:iam:policy",
		"resource_id": "my-project",
		"data": {
			"bindings": [
				{"role": "roles/editor", "members": ["user:dev@example.com"]},
			],
		},
	}
	count(result) == 1
}

# Test: multiple members with owner should create multiple violations
test_multiple_members if {
	result := cc6_3_permissive.violations with input as {
		"resource_type": "gcp:iam:policy",
		"resource_id": "my-project",
		"data": {
			"bindings": [
				{"role": "roles/owner", "members": ["user:a@example.com", "user:b@example.com"]},
			],
		},
	}
	count(result) == 2
}

# Test: viewer role should pass
test_viewer_role if {
	result := cc6_3_permissive.violations with input as {
		"resource_type": "gcp:iam:policy",
		"resource_id": "my-project",
		"data": {
			"bindings": [
				{"role": "roles/viewer", "members": ["user:reader@example.com"]},
			],
		},
	}
	count(result) == 0
}

# Test: granular role should pass
test_granular_role if {
	result := cc6_3_permissive.violations with input as {
		"resource_type": "gcp:iam:policy",
		"resource_id": "my-project",
		"data": {
			"bindings": [
				{"role": "roles/storage.objectViewer", "members": ["user:app@example.com"]},
			],
		},
	}
	count(result) == 0
}

# Negative: wrong resource type should not trigger
test_wrong_resource_type if {
	result := cc6_3_permissive.violations with input as {
		"resource_type": "aws:iam:user",
		"resource_id": "arn:aws:iam::123:user/bob",
		"data": {
			"bindings": [
				{"role": "roles/owner", "members": ["user:admin@example.com"]},
			],
		},
	}
	count(result) == 0
}

# Negative: empty data should not trigger
test_empty_data if {
	result := cc6_3_permissive.violations with input as {
		"resource_type": "gcp:iam:policy",
		"resource_id": "my-project",
		"data": {},
	}
	count(result) == 0
}

# Negative: empty bindings array should not trigger
test_empty_bindings if {
	result := cc6_3_permissive.violations with input as {
		"resource_type": "gcp:iam:policy",
		"resource_id": "my-project",
		"data": {
			"bindings": [],
		},
	}
	count(result) == 0
}

# Negative: binding with empty members should not trigger
test_empty_members if {
	result := cc6_3_permissive.violations with input as {
		"resource_type": "gcp:iam:policy",
		"resource_id": "my-project",
		"data": {
			"bindings": [
				{"role": "roles/owner", "members": []},
			],
		},
	}
	count(result) == 0
}
