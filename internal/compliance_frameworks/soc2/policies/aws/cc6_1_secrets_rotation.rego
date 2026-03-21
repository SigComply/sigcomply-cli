# METADATA
# title: CC6.1 - Secrets Manager Rotation
# description: Secrets must have rotation enabled and be rotated within 90 days
# scope: package
package sigcomply.soc2.cc6_1_secrets_rotation

metadata := {
	"id": "soc2-cc6.1-secrets-rotation",
	"name": "Secrets Manager Rotation Enabled",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:secretsmanager:secret"],
	"remediation": "Enable rotation: aws secretsmanager rotate-secret --secret-id SECRET_NAME --rotation-rules AutomaticallyAfterDays=90",
}

violations contains violation if {
	input.resource_type == "aws:secretsmanager:secret"
	input.data.rotation_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Secret '%s' does not have rotation enabled", [input.data.name]),
		"details": {
			"name": input.data.name,
			"rotation_enabled": false,
		},
	}
}

violations contains violation if {
	input.resource_type == "aws:secretsmanager:secret"
	input.data.rotation_enabled == true
	input.data.days_since_rotation > 90
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Secret '%s' has not been rotated in %d days (max 90)", [input.data.name, input.data.days_since_rotation]),
		"details": {
			"name": input.data.name,
			"days_since_rotation": input.data.days_since_rotation,
		},
	}
}
