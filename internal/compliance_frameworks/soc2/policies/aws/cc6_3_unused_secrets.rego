# METADATA
# title: CC6.3 - Unused Secrets Removal
# description: Secrets Manager secrets unused for extended periods should be removed
# scope: package
package sigcomply.soc2.cc6_3_unused_secrets

metadata := {
	"id": "soc2-cc6.3-unused-secrets",
	"name": "Unused Secrets Removal",
	"framework": "soc2",
	"control": "CC6.3",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:secretsmanager:secret"],
	"remediation": "Review and remove secrets that have not been accessed in over 90 days. If still needed, document the reason for retention.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:secretsmanager:secret"
	input.data.days_since_last_accessed > 90
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Secret '%s' has not been accessed in %d days (threshold: 90)", [input.data.secret_name, input.data.days_since_last_accessed]),
		"details": {
			"secret_name": input.data.secret_name,
			"days_since_last_accessed": input.data.days_since_last_accessed,
		},
	}
}
