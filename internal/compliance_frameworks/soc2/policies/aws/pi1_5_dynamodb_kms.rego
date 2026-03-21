# METADATA
# title: PI1.5 - DynamoDB CMK Encryption
# description: DynamoDB tables should use customer-managed KMS keys for encryption
# scope: package
package sigcomply.soc2.pi1_5_dynamodb_kms

metadata := {
	"id": "soc2-pi1.5-dynamodb-kms",
	"name": "DynamoDB CMK Encryption",
	"framework": "soc2",
	"control": "PI1.5",
	"severity": "medium",
	"evaluation_mode": "individual",
	"resource_types": ["aws:dynamodb:table"],
	"remediation": "Configure DynamoDB table to use a customer-managed KMS key (CMK) for encryption.",
}

violations contains violation if {
	input.resource_type == "aws:dynamodb:table"
	input.data.encryption_type != "KMS"
	violation := {
		"resource_id": input.resource_id,
		"resource_type": input.resource_type,
		"reason": sprintf("DynamoDB table '%s' does not use customer-managed KMS encryption (uses: %s)", [input.data.name, input.data.encryption_type]),
		"details": {"table_name": input.data.name, "encryption_type": input.data.encryption_type},
	}
}
