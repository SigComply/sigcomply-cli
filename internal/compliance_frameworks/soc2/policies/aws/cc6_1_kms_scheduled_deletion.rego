# METADATA
# title: CC6.1 - KMS Key Not Scheduled for Deletion
# description: KMS keys should not be unintentionally scheduled for deletion
# scope: package
package sigcomply.soc2.cc6_1_kms_scheduled_deletion

metadata := {
	"id": "soc2-cc6.1-kms-scheduled-deletion",
	"name": "KMS Key Scheduled for Deletion",
	"framework": "soc2",
	"control": "CC6.1",
	"severity": "high",
	"evaluation_mode": "individual",
	"resource_types": ["aws:kms:key"],
	"remediation": "Cancel the key deletion if unintended: aws kms cancel-key-deletion --key-id <key-id>. Review key usage before allowing deletion to proceed.",
	"evidence_type": "automated",
}

violations contains violation if {
	input.resource_type == "aws:kms:key"
	input.data.key_state == "PendingDeletion"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("KMS key '%s' is scheduled for deletion", [input.data.key_id]),
		"details": {
			"key_id": input.data.key_id,
			"key_state": input.data.key_state,
		},
	}
}
