# METADATA
# title: CC6.1 - KMS Key Rotation
# description: Customer-managed KMS keys must have automatic rotation enabled
# scope: package
package sigcomply.soc2.cc6_1_kms_rotation

metadata := {
	"id": "soc2-cc6.1-kms-rotation",
	"name": "KMS Key Auto-Rotation",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:kms:key"],
	"remediation": "Enable automatic key rotation for KMS keys: aws kms enable-key-rotation --key-id <key-id>",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:kms:key"
	input.data.enabled == true
	input.data.rotation_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("KMS key '%s' does not have automatic rotation enabled", [input.data.key_id]),
		"details": {
			"key_id": input.data.key_id,
			"key_state": input.data.key_state,
		},
	}
}
