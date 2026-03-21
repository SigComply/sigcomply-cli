package sigcomply.soc2.cc6_8_eks_supported_version_test

import data.sigcomply.soc2.cc6_8_eks_supported_version

test_eol_version_violation if {
	result := cc6_8_eks_supported_version.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/my-cluster",
		"data": {
			"name": "my-cluster",
			"version": "1.24",
		},
	}
	count(result) == 1
}

test_supported_version_pass if {
	result := cc6_8_eks_supported_version.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/my-cluster",
		"data": {
			"name": "my-cluster",
			"version": "1.29",
		},
	}
	count(result) == 0
}

test_latest_version_pass if {
	result := cc6_8_eks_supported_version.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/my-cluster",
		"data": {
			"name": "my-cluster",
			"version": "1.31",
		},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_eks_supported_version.violations with input as {
		"resource_type": "aws:rds:instance",
		"resource_id": "arn:aws:rds:us-east-1:123:db:mydb",
		"data": {"version": "1.24"},
	}
	count(result) == 0
}
