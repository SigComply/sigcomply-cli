package sigcomply.soc2.cc7_3_vpc_flow_logs_test

import data.sigcomply.soc2.cc7_3_vpc_flow_logs

test_no_flow_logs if {
	result := cc7_3_vpc_flow_logs.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "vpc-123",
		"data": {"vpc_id": "vpc-123", "flow_logs_enabled": false},
	}
	count(result) == 1
}

test_flow_logs_enabled if {
	result := cc7_3_vpc_flow_logs.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "vpc-123",
		"data": {"vpc_id": "vpc-123", "flow_logs_enabled": true},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_3_vpc_flow_logs.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc7_3_vpc_flow_logs.violations with input as {
		"resource_type": "aws:ec2:vpc",
		"resource_id": "test-resource",
		"data": {},
	}
	count(result) == 0
}
