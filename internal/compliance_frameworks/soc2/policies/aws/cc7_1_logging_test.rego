package sigcomply.soc2.cc7_1_test

import data.sigcomply.soc2.cc7_1

# Negative: no trails exist at all
test_no_trails if {
	result := cc7_1.violations with input as {
		"resources": [],
	}
	count(result) == 1
}

# Negative: trails exist but none logging
test_trails_not_logging if {
	result := cc7_1.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
				"data": {
					"name": "my-trail",
					"is_logging": false,
					"log_file_validation": false,
					"is_multi_region": false,
				},
			},
		],
	}
	# Should have violation for "no trail is logging"
	count(result) == 1
}

# Negative: logging but no validation and not multi-region (2 warnings)
test_logging_no_validation_no_multiregion if {
	result := cc7_1.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
				"data": {
					"name": "my-trail",
					"is_logging": true,
					"log_file_validation": false,
					"is_multi_region": false,
				},
			},
		],
	}
	# 2 warnings: no validation + no multi-region
	count(result) == 2
}

# Positive: fully configured trail (logging, validation, multi-region)
test_fully_configured if {
	result := cc7_1.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
				"data": {
					"name": "my-trail",
					"is_logging": true,
					"log_file_validation": true,
					"is_multi_region": true,
				},
			},
		],
	}
	count(result) == 0
}

# Positive: multiple trails, at least one fully configured
test_multiple_trails_one_good if {
	result := cc7_1.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/bad-trail",
				"data": {
					"name": "bad-trail",
					"is_logging": false,
					"log_file_validation": false,
					"is_multi_region": false,
				},
			},
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/good-trail",
				"data": {
					"name": "good-trail",
					"is_logging": true,
					"log_file_validation": true,
					"is_multi_region": true,
				},
			},
		],
	}
	count(result) == 0
}

# Edge: logging with validation but not multi-region (1 warning)
test_logging_validated_not_multiregion if {
	result := cc7_1.violations with input as {
		"resources": [
			{
				"resource_type": "aws:cloudtrail:trail",
				"resource_id": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
				"data": {
					"name": "my-trail",
					"is_logging": true,
					"log_file_validation": true,
					"is_multi_region": false,
				},
			},
		],
	}
	# 1 warning: no multi-region
	count(result) == 1
}
