package sigcomply.soc2.cc6_8_lambda_runtime_test

import data.sigcomply.soc2.cc6_8_lambda_runtime

# Test: deprecated runtime should violate
test_deprecated_nodejs if {
	result := cc6_8_lambda_runtime.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"function_name": "my-func",
			"runtime": "nodejs14.x",
		},
	}
	count(result) == 1
}

# Test: deprecated python runtime should violate
test_deprecated_python if {
	result := cc6_8_lambda_runtime.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:py-func",
		"data": {
			"function_name": "py-func",
			"runtime": "python3.7",
		},
	}
	count(result) == 1
}

# Test: supported runtime should pass
test_supported_runtime if {
	result := cc6_8_lambda_runtime.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:my-func",
		"data": {
			"function_name": "my-func",
			"runtime": "nodejs20.x",
		},
	}
	count(result) == 0
}

# Test: container image (null runtime) should pass
test_container_image if {
	result := cc6_8_lambda_runtime.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:container-func",
		"data": {
			"function_name": "container-func",
			"runtime": null,
		},
	}
	count(result) == 0
}

# Negative: wrong resource type
test_wrong_resource_type if {
	result := cc6_8_lambda_runtime.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"runtime": "nodejs14.x"},
	}
	count(result) == 0
}
