package sigcomply.soc2.cc6_6_flow_logs_test

import data.sigcomply.soc2.cc6_6_flow_logs

# Test: VPC without flow logs should violate
test_vpc_no_flow_logs if {
	result := cc6_6_flow_logs.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "arn:aws:ec2::123:vpc/vpc-1",
		"data": {
			"vpc_id": "vpc-1",
			"is_default": false,
			"flow_logs_enabled": false,
		},
	}
	count(result) == 1
}

# Test: VPC with flow logs should pass
test_vpc_with_flow_logs if {
	result := cc6_6_flow_logs.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "arn:aws:ec2::123:vpc/vpc-2",
		"data": {
			"vpc_id": "vpc-2",
			"is_default": false,
			"flow_logs_enabled": true,
		},
	}
	count(result) == 0
}

# Test: GCP subnet without flow logs should violate
test_gcp_subnet_no_flow_logs if {
	result := cc6_6_flow_logs.violations with input as {
		"resource_type": "gcp:compute:subnet",
		"resource_id": "projects/proj/regions/us-central1/subnetworks/sub-1",
		"data": {
			"name": "sub-1",
			"region": "us-central1",
			"flow_logs_enabled": false,
		},
	}
	count(result) == 1
}

# Test: GCP subnet with flow logs should pass
test_gcp_subnet_with_flow_logs if {
	result := cc6_6_flow_logs.violations with input as {
		"resource_type": "gcp:compute:subnet",
		"resource_id": "projects/proj/regions/us-central1/subnetworks/sub-2",
		"data": {
			"name": "sub-2",
			"region": "us-central1",
			"flow_logs_enabled": true,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_6_flow_logs.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"flow_logs_enabled": false},
	}
	count(result) == 0
}

# Negative: empty data for VPC
test_vpc_empty_data if {
	result := cc6_6_flow_logs.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "arn:aws:ec2::123:vpc/vpc-empty",
		"data": {},
	}
	count(result) == 0
}

# Negative: empty data for GCP subnet
test_gcp_subnet_empty_data if {
	result := cc6_6_flow_logs.violations with input as {
		"resource_type": "gcp:compute:subnet",
		"resource_id": "projects/proj/regions/us-central1/subnetworks/empty",
		"data": {},
	}
	count(result) == 0
}
