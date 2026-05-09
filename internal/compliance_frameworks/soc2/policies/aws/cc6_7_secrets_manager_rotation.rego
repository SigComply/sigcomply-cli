# METADATA
# title: CC6.7 - Secrets Manager Rotation
# description: Secrets Manager secrets should have automatic rotation enabled
# scope: package
package sigcomply.soc2.cc6_7_secrets_manager_rotation

metadata := {
	"id": "soc2-cc6.7-secrets-manager-rotation",
	"name": "Secrets Manager Rotation",
	"framework": "soc2",
	"control": "CC6.7",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:secretsmanager:secret"],
	"remediation": "Enable automatic rotation for the secret in AWS Secrets Manager to ensure credentials are regularly rotated.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:secretsmanager:secret"
	input.data.rotation_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Secret '%s' does not have automatic rotation enabled", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
