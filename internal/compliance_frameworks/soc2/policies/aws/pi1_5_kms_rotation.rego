# METADATA
# title: PI1.5 - KMS Key Rotation
# description: KMS customer-managed keys should have automatic rotation enabled
# scope: package
package sigcomply.soc2.pi1_5_kms_rotation

metadata := {
	"id": "soc2-pi1.5-kms-rotation",
	"name": "KMS CMK Rotation Enabled",
	"framework": "soc2",
	"control": "PI1.5",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:kms:key"],
	"remediation": "Enable automatic key rotation: aws kms enable-key-rotation --key-id <key-id>",
}

violations contains violation if {
	input.resource_type == "aws:kms:key"
	input.data.key_manager == "CUSTOMER"
	input.data.rotation_enabled == false
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("KMS key '%s' does not have automatic rotation enabled", [input.data.key_id]),
		"details": {"key_id": input.data.key_id},
	}
}
