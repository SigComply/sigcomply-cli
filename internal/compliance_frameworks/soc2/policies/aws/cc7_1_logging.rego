# METADATA
# title: CC7.1 - CloudTrail Logging Required
# description: At least one CloudTrail trail must be enabled and logging
# scope: package
# schemas:
#   - input: schema.input
package sigcomply.soc2.cc7_1

metadata := {
	"id": "soc2-cc7.1-logging",
	"name": "CloudTrail Logging Required",
	"framework": "soc2",
	"control": "CC7.1",
	"severity": "critical",
	"evaluation_mode": "batched",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable CloudTrail logging: aws cloudtrail start-logging --name <trail-name>",
}

# Check if any trail is actively logging
default any_trail_logging := false

any_trail_logging if {
	some i
	input.resources[i].data.is_logging == true
}

# Check if any trail has log file validation enabled
default any_trail_validated := false

any_trail_validated if {
	some i
	input.resources[i].data.log_file_validation == true
}

# Check if any trail is multi-region
default any_trail_multiregion := false

any_trail_multiregion if {
	some i
	input.resources[i].data.is_multi_region == true
}

# Violation: No trails are logging
violations contains violation if {
	count(input.resources) > 0
	not any_trail_logging
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail is actively logging. At least one trail must be enabled.",
		"details": {
			"total_trails": count(input.resources),
		},
	}
}

# Violation: No trails exist at all
violations contains violation if {
	count(input.resources) == 0
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trails configured. Create and enable at least one trail for audit logging.",
		"details": {},
	}
}

# Warning: No trail has log file validation
violations contains violation if {
	count(input.resources) > 0
	any_trail_logging
	not any_trail_validated
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail has log file validation enabled. Enable validation to detect log tampering.",
		"details": {
			"severity_override": "medium",
		},
	}
}

# Warning: No multi-region trail
violations contains violation if {
	count(input.resources) > 0
	any_trail_logging
	not any_trail_multiregion
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail is configured for multi-region. Consider enabling multi-region for complete coverage.",
		"details": {
			"severity_override": "low",
		},
	}
}
