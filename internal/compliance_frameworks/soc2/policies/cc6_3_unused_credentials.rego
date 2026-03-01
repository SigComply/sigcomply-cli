# METADATA
# title: CC6.3 - Unused Credentials Cleanup
# description: IAM users inactive for 90+ days should be disabled or removed
# scope: package
package sigcomply.soc2.cc6_3_unused

metadata := {
	"id": "soc2-cc6.3-unused-credentials",
	"name": "Unused Credentials Cleanup",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["gcp:iam:service-account"],
	"remediation": "Disable or delete service accounts that have been inactive for more than 90 days.",
}

violations contains violation if {
	input.resource_type == "gcp:iam:service-account"
	input.data.disabled == false
	input.data.key_count == 0
	# Service accounts with no keys and not disabled may be unused
	# This is a soft check — presence of keys indicates active use
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Service account '%s' has no user-managed keys and may be unused", [input.data.email]),
		"details": {
			"email": input.data.email,
			"severity_override": "low",
		},
	}
}
