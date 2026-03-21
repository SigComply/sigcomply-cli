package sigcomply.soc2.cc7_1_lambda_xray_tracing_test

import data.sigcomply.soc2.cc7_1_lambda_xray_tracing

test_passthrough_mode if {
	result := cc7_1_lambda_xray_tracing.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:myfunc",
		"data": {"name": "myfunc", "tracing_mode": "PassThrough"},
	}
	count(result) == 1
}

test_active_mode if {
	result := cc7_1_lambda_xray_tracing.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:myfunc",
		"data": {"name": "myfunc", "tracing_mode": "Active"},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc7_1_lambda_xray_tracing.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "test",
		"data": {},
	}
	count(result) == 0
}
