package sigcomply.soc2.cc6_6_eks_endpoint_public_test

import data.sigcomply.soc2.cc6_6_eks_endpoint_public

test_public_endpoint_violation if {
	result := cc6_6_eks_endpoint_public.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/dev",
		"data": {"name": "dev", "endpoint_public_access": true},
	}
	count(result) == 1
}

test_private_endpoint_pass if {
	result := cc6_6_eks_endpoint_public.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/prod",
		"data": {"name": "prod", "endpoint_public_access": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_6_eks_endpoint_public.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"endpoint_public_access": true},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_6_eks_endpoint_public.violations with input as {
		"resource_type": "aws:eks:cluster",
		"resource_id": "arn:aws:eks:us-east-1:123:cluster/test",
		"data": {},
	}
	count(result) == 0
}
