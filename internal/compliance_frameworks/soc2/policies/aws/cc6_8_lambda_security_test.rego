package sigcomply.soc2.cc6_8_lambda_security_test

import data.sigcomply.soc2.cc6_8_lambda_security

test_deprecated_runtime if {
	result := cc6_8_lambda_security.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:old",
		"data": {"name": "old", "runtime": "python2.7", "runtime_deprecated": true, "publicly_accessible": false},
	}
	count(result) == 1
}

test_publicly_accessible if {
	result := cc6_8_lambda_security.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:public",
		"data": {"name": "public", "runtime": "python3.12", "runtime_deprecated": false, "publicly_accessible": true},
	}
	count(result) == 1
}

# Both violations simultaneously
test_both_violations if {
	result := cc6_8_lambda_security.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:bad",
		"data": {"name": "bad", "runtime": "python2.7", "runtime_deprecated": true, "publicly_accessible": true},
	}
	count(result) == 2
}

test_secure_function if {
	result := cc6_8_lambda_security.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:secure",
		"data": {"name": "secure", "runtime": "python3.12", "runtime_deprecated": false, "publicly_accessible": false},
	}
	count(result) == 0
}

test_wrong_resource_type if {
	result := cc6_8_lambda_security.violations with input as {
		"resource_type": "aws:s3:bucket",
		"resource_id": "arn:aws:s3:::bucket",
		"data": {"runtime_deprecated": true},
	}
	count(result) == 0
}

test_empty_data if {
	result := cc6_8_lambda_security.violations with input as {
		"resource_type": "aws:lambda:function",
		"resource_id": "arn:aws:lambda:us-east-1:123:function:test",
		"data": {},
	}
	count(result) == 0
}
