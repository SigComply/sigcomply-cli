# METADATA
# title: A.12.4.1 - Event Logging
# description: Event logs recording user activities, exceptions, faults and security events shall be produced, kept and regularly reviewed
# scope: package
# schemas:
#   - input: schema.input
package tracevault.iso27001.a_12_4_1

metadata := {
	"id": "iso27001-a.12.4.1-logging",
	"name": "Event Logging",
	"framework": "iso27001",
	"control": "A.12.4.1",
	"severity": "critical",
	"evaluation_mode": "batched",
	"resource_types": ["aws:cloudtrail:trail"],
	"remediation": "Enable CloudTrail logging with log file validation. Ensure trails cover all regions and have proper retention.",
}

# Check if any trail is actively logging
default any_trail_logging := false

any_trail_logging if {
	some i
	input.resources[i].data.is_logging == true
}

# Check if any trail has log file validation enabled (protection against tampering - A.12.4.2)
default any_trail_validated := false

any_trail_validated if {
	some i
	input.resources[i].data.log_file_validation == true
}

# Check if any trail is multi-region (comprehensive coverage)
default any_trail_multiregion := false

any_trail_multiregion if {
	some i
	input.resources[i].data.is_multi_region == true
}

# Violation: No trails are logging - critical for A.12.4.1
violations contains violation if {
	count(input.resources) > 0
	not any_trail_logging
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail is actively logging. Event logging is required for ISO 27001 A.12.4.1 compliance.",
		"details": {
			"total_trails": count(input.resources),
			"control": "A.12.4.1",
		},
	}
}

# Violation: No trails exist at all
violations contains violation if {
	count(input.resources) == 0
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trails configured. Create and enable at least one trail for event logging as required by ISO 27001 A.12.4.1.",
		"details": {
			"control": "A.12.4.1",
		},
	}
}

# Violation: No trail has log file validation (relates to A.12.4.2 - Protection of Log Information)
violations contains violation if {
	count(input.resources) > 0
	any_trail_logging
	not any_trail_validated
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail has log file validation enabled. Log integrity validation is required to detect tampering (ISO 27001 A.12.4.2).",
		"details": {
			"severity_override": "high",
			"control": "A.12.4.1",
			"related_control": "A.12.4.2",
		},
	}
}

# Violation: No multi-region trail (comprehensive event coverage)
violations contains violation if {
	count(input.resources) > 0
	any_trail_logging
	not any_trail_multiregion
	violation := {
		"resource_id": "aws-account",
		"resource_type": "aws:account",
		"reason": "No CloudTrail trail is configured for multi-region. Consider enabling multi-region for comprehensive event logging coverage.",
		"details": {
			"severity_override": "medium",
			"control": "A.12.4.1",
		},
	}
}
