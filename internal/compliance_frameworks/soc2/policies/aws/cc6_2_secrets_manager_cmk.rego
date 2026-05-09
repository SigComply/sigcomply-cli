# METADATA
# title: CC6.2 - Secrets Manager CMK Encryption
# description: Secrets Manager secrets should be encrypted with a customer-managed KMS key
# scope: package
package sigcomply.soc2.cc6_2_secrets_manager_cmk

metadata := {
	"id": "soc2-cc6.2-secrets-manager-cmk",
	"name": "Secrets Manager CMK Encryption",
	"framework": "soc2",
	"control": "CC6.2",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:secretsmanager:secret"],
	"remediation": "Update the secret to use a CMK: aws secretsmanager update-secret --secret-id SECRET --kms-key-id KEY_ARN",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:secretsmanager:secret"
	input.data.cmk_encrypted == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("Secrets Manager secret '%s' is not encrypted with a customer-managed KMS key", [input.data.name]),
		"details": {"name": input.data.name},
	}
}
